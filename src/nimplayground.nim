import prologue
import std/asyncdispatch
import json
import osproc
import os
import strutils
import times
import tables
import db_connector/db_sqlite
import std/[locks, sequtils, sysrand, base64]
import taskpools
import nimcrypto/[hash, sha2]

const
  AllowedLanguages = [
    "python", "javascript", "ruby", "php", "lua", "perl",
    "c", "cpp", "rust", "go", "java", "nim",
    "python-ds", "cpp-drogon"
  ]
  MaxCodeBytes = 65536
  MaxOutputBytes = 65536
  MaxConcurrentExecutions = 2
  RunRequestsPerMinute = 20
  SnippetRequestsPerMinute = 20
  SnippetReadRequestsPerMinute = 60
  HealthRequestsPerMinute = 30
  SnippetTtlDays = 30
  MaxStoredSnippets = 20000
  SnippetPurgeIntervalSeconds = 3600
  RuntimeCheckCacheSeconds = 10.0
  DataRoot = "data"
  DbPath = DataRoot / "snippets.db"
  SandboxRoot = "sandbox"

type
  SandboxSpec = object
    fileName: string
    image: string
    command: string
    timeoutSeconds: int
    memory: string
    cpus: string
    pids: int
    tmpfsSize: string
    env: seq[string]

  RunResult = object
    output: string
    exitCode: int

  # Fixed-size mirror of RunResult: taskpools Flowvars only carry types that
  # support copyMem, so results cross threads in this buffer.
  RunResultMsg = object
    exitCode: int32
    outputLen: int32
    output: array[MaxOutputBytes + 512, char]

var
  execLock: Lock
  activeExecutions: int
  dbLock: Lock
  rateLock: Lock
  requestWindows: Table[string, seq[float]]
  lastRateSweep: float
  indexHtml: string
  cspHeader: string
  execPool: Taskpool
  runtimeStatusLock: Lock
  runtimeCheckedAt: float
  runtimeStatusOk: bool

initLock(execLock)
initLock(dbLock)
initLock(rateLock)
initLock(runtimeStatusLock)

proc initDb() =
  acquire(dbLock)
  try:
    createDir(DataRoot)
    let db = open(DbPath, "", "", "")
    try:
      db.exec(sql"""
        CREATE TABLE IF NOT EXISTS snippets (
          id TEXT PRIMARY KEY,
          code TEXT NOT NULL,
          language TEXT NOT NULL,
          created_at INTEGER NOT NULL DEFAULT 0
        )
      """)
      let cols = db.getAllRows(sql"PRAGMA table_info(snippets)")
      if not cols.anyIt(it[1] == "created_at"):
        db.exec(sql"ALTER TABLE snippets ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")
      db.exec(sql"DELETE FROM snippets WHERE created_at > 0 AND created_at < ?", epochTime().int - SnippetTtlDays * 24 * 60 * 60)
    finally:
      db.close()
  finally:
    release(dbLock)

proc randomHex(byteCount: int): string =
  const hex = "0123456789abcdef"
  let bytes = urandom(byteCount)
  result = newStringOfCap(byteCount * 2)
  for b in bytes:
    result.add(hex[int(b shr 4)])
    result.add(hex[int(b and 0x0f)])

proc isAllowedLanguage(language: string): bool =
  language in AllowedLanguages

proc isHexId(id: string): bool =
  result = id.len == 32
  if not result:
    return
  for ch in id:
    if ch notin {'0'..'9', 'a'..'f'}:
      return false

proc inlineContentHash(html, tag: string): string =
  # CSP hash for the first inline <script>/<style> block, matching what the
  # browser hashes: the exact bytes between the tags.
  let openIdx = html.find("<" & tag)
  if openIdx < 0:
    return ""
  let contentStart = html.find('>', openIdx)
  if contentStart < 0:
    return ""
  let closeIdx = html.find("</" & tag & ">", contentStart)
  if closeIdx < 0:
    return ""
  let content = html[contentStart + 1 ..< closeIdx]
  "'sha256-" & base64.encode(sha256.digest(content).data) & "'"

proc buildCsp(html: string): string =
  let scriptHash = inlineContentHash(html, "script")
  let styleHash = inlineContentHash(html, "style")
  result = "default-src 'none'"
  result &= "; script-src 'self'" & (if scriptHash.len > 0: " " & scriptHash else: "")
  result &= "; style-src 'self'" & (if styleHash.len > 0: " " & styleHash else: "")
  result &= "; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"

proc securityHeaders(includeCsp = false): ResponseHeaders =
  result = initResponseHeaders({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
  })
  if includeCsp:
    {.cast(gcsafe).}:
      result["Content-Security-Policy"] = cspHeader

proc shellQuote(value: string): string =
  "'" & value.replace("'", "'\\''") & "'"

proc sandboxUser(): string =
  getEnv("SANDBOX_UID", "997") & ":" & getEnv("SANDBOX_GID", "986")

proc sandboxRuntime(): string =
  getEnv("SANDBOX_RUNTIME", "runsc").strip()

proc probeSandboxRuntime(): bool =
  let runtime = sandboxRuntime()
  if runtime.len == 0:
    return true
  let (output, exitCode) = execCmdEx("docker info --format '{{json .Runtimes}}' 2>/dev/null")
  exitCode == 0 and output.contains("\"" & runtime & "\"")

proc sandboxRuntimeAvailable(): bool {.gcsafe.} =
  # Probing shells out to the Docker CLI, so cache the result briefly to keep
  # /healthz and per-run checks from blocking the event loop.
  {.cast(gcsafe).}:
    acquire(runtimeStatusLock)
    if epochTime() - runtimeCheckedAt < RuntimeCheckCacheSeconds:
      result = runtimeStatusOk
      release(runtimeStatusLock)
      return
    release(runtimeStatusLock)

    let ok = probeSandboxRuntime()
    acquire(runtimeStatusLock)
    runtimeStatusOk = ok
    runtimeCheckedAt = epochTime()
    release(runtimeStatusLock)
    result = ok

proc clientIp(ctx: Context): string =
  # Trust only X-Real-IP: Nginx overwrites it on every proxied request,
  # while X-Forwarded-For is client-controlled and would let callers pick
  # their own rate-limit identity.
  let headers = ctx.request.headers
  if headers.hasKey("X-Real-IP"):
    return headers["X-Real-IP", 0].strip()
  ctx.request.hostName()

proc allowRequest(ctx: Context, bucket: string, limit: int): bool =
  let now = epochTime()
  let cutoff = now - 60.0
  let key = bucket & ":" & clientIp(ctx)

  acquire(rateLock)
  try:
    if now - lastRateSweep >= 60.0:
      lastRateSweep = now
      var stale: seq[string]
      for existing, window in requestWindows:
        if not window.anyIt(it >= cutoff):
          stale.add(existing)
      for existing in stale:
        requestWindows.del(existing)

    var window = requestWindows.getOrDefault(key, @[])
    window = window.filterIt(it >= cutoff)
    result = window.len < limit
    if result:
      window.add(now)
    if window.len == 0:
      requestWindows.del(key)
    else:
      requestWindows[key] = window
  finally:
    release(rateLock)

proc wantsJson(ctx: Context): bool =
  ctx.request.contentType().toLowerAscii().startsWith("application/json")

proc errorResponse(message: string, code: HttpCode): Response =
  jsonResponse(%*{"message": message}, code, headers = securityHeaders())

proc tryAcquireExecution(): bool {.gcsafe.} =
  acquire(execLock)
  if activeExecutions >= MaxConcurrentExecutions:
    release(execLock)
    return false
  inc activeExecutions
  release(execLock)
  true

proc releaseExecution() {.gcsafe.} =
  acquire(execLock)
  if activeExecutions > 0:
    dec activeExecutions
  release(execLock)

proc getSpec(language: string): SandboxSpec =
  case language
  of "python":
    SandboxSpec(
      fileName: "snippet.py",
      image: "python:3.13-alpine",
      command: "python -u /app/snippet.py",
      timeoutSeconds: 10,
      memory: "64m",
      cpus: "0.5",
      pids: 64,
      tmpfsSize: "32m",
      env: @["HOME=/tmp", "PYTHONDONTWRITEBYTECODE=1"]
    )
  of "javascript":
    SandboxSpec(
      fileName: "snippet.js",
      image: "node:24-alpine",
      command: "node /app/snippet.js",
      timeoutSeconds: 10,
      memory: "64m",
      cpus: "0.5",
      pids: 64,
      tmpfsSize: "32m",
      env: @["HOME=/tmp"]
    )
  of "ruby":
    SandboxSpec(
      fileName: "snippet.rb",
      image: "ruby:3.4-alpine",
      command: "ruby /app/snippet.rb",
      timeoutSeconds: 10,
      memory: "64m",
      cpus: "0.5",
      pids: 64,
      tmpfsSize: "32m",
      env: @["HOME=/tmp"]
    )
  of "php":
    SandboxSpec(
      fileName: "snippet.php",
      image: "php:8.4-cli-alpine",
      command: "php /app/snippet.php",
      timeoutSeconds: 10,
      memory: "64m",
      cpus: "0.5",
      pids: 64,
      tmpfsSize: "32m",
      env: @["HOME=/tmp"]
    )
  of "lua":
    SandboxSpec(
      fileName: "snippet.lua",
      image: "lua-playground",
      command: "lua /app/snippet.lua",
      timeoutSeconds: 10,
      memory: "64m",
      cpus: "0.5",
      pids: 64,
      tmpfsSize: "32m",
      env: @["HOME=/tmp"]
    )
  of "perl":
    SandboxSpec(
      fileName: "snippet.pl",
      image: "perl:5.40-slim",
      command: "perl /app/snippet.pl",
      timeoutSeconds: 10,
      memory: "64m",
      cpus: "0.5",
      pids: 64,
      tmpfsSize: "32m",
      env: @["HOME=/tmp"]
    )
  of "c":
    SandboxSpec(
      fileName: "snippet.c",
      image: "gcc:14",
      command: "cd /tmp && cp /app/snippet.c . && gcc snippet.c -O0 -pipe -o prog && ./prog",
      timeoutSeconds: 15,
      memory: "128m",
      cpus: "1.0",
      pids: 64,
      tmpfsSize: "64m",
      env: @["HOME=/tmp"]
    )
  of "cpp":
    SandboxSpec(
      fileName: "snippet.cpp",
      image: "gcc:14",
      command: "cd /tmp && cp /app/snippet.cpp . && g++ snippet.cpp -O0 -pipe -o prog && ./prog",
      timeoutSeconds: 15,
      memory: "128m",
      cpus: "1.0",
      pids: 64,
      tmpfsSize: "64m",
      env: @["HOME=/tmp"]
    )
  of "rust":
    SandboxSpec(
      fileName: "snippet.rs",
      image: "rust:1-alpine",
      command: "cd /tmp && cp /app/snippet.rs . && rustc snippet.rs -o prog && ./prog",
      timeoutSeconds: 35,
      memory: "256m",
      cpus: "1.0",
      pids: 64,
      tmpfsSize: "128m",
      env: @["HOME=/tmp"]
    )
  of "go":
    SandboxSpec(
      fileName: "snippet.go",
      image: "golang:1.25-alpine",
      command: "cd /tmp && cp /app/snippet.go . && go build -trimpath -o prog snippet.go && ./prog",
      timeoutSeconds: 35,
      memory: "256m",
      cpus: "1.0",
      pids: 256,
      tmpfsSize: "128m",
      env: @["HOME=/tmp", "GOCACHE=/tmp/.cache", "GO111MODULE=off", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off"]
    )
  of "java":
    SandboxSpec(
      fileName: "Snippet.java",
      image: "eclipse-temurin:25-jdk-alpine",
      command: "cd /tmp && cp /app/Snippet.java . && javac Snippet.java && java -Xmx96m -XX:ActiveProcessorCount=1 Snippet",
      timeoutSeconds: 25,
      memory: "384m",
      cpus: "1.0",
      pids: 128,
      tmpfsSize: "128m",
      env: @["HOME=/tmp"]
    )
  of "nim":
    SandboxSpec(
      fileName: "snippet.nim",
      image: "nimlang/nim:2.2.4-alpine",
      command: "cd /tmp && cp /app/snippet.nim . && nim c --hints:off --verbosity:0 -d:release -o:prog snippet.nim && ./prog",
      timeoutSeconds: 35,
      memory: "256m",
      cpus: "1.0",
      pids: 128,
      tmpfsSize: "128m",
      env: @["HOME=/tmp"]
    )
  of "python-ds":
    SandboxSpec(
      fileName: "snippet.py",
      image: "python-ds",
      command: "python -u /app/snippet.py",
      timeoutSeconds: 10,
      memory: "128m",
      cpus: "1.0",
      pids: 128,
      tmpfsSize: "64m",
      env: @["HOME=/tmp", "PYTHONDONTWRITEBYTECODE=1", "MPLCONFIGDIR=/tmp"]
    )
  of "cpp-drogon":
    SandboxSpec(
      fileName: "snippet.cpp",
      image: "cpp-drogon",
      command: "cd /tmp && cp /app/snippet.cpp . && g++ -O0 -std=c++17 snippet.cpp -I/usr/include/jsoncpp -ldrogon -ltrantor -ljsoncpp -luuid -lz -lssl -lcrypto -lcares -lpq -lhiredis -lsqlite3 -lmariadb -lpthread -o prog && ./prog",
      timeoutSeconds: 35,
      memory: "512m",
      cpus: "1.0",
      pids: 256,
      tmpfsSize: "256m",
      env: @["HOME=/tmp"]
    )
  else:
    raise newException(ValueError, "unsupported language")

proc dockerCommand(spec: SandboxSpec, execDir, containerName: string): string =
  var args = @["run"]
  let runtime = sandboxRuntime()
  if runtime.len > 0:
    args.add("--runtime")
    args.add(runtime)
  args.add(@[
    "--rm",
    "--name", containerName,
    "-i",
    "--user", sandboxUser(),
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--security-opt", "apparmor=docker-default",
    "--network", "none",
    "--ipc", "none",
    "--read-only",
    "--pids-limit", $spec.pids,
    "--ulimit", "nofile=256:256",
    "--memory", spec.memory,
    "--cpus", spec.cpus,
    "-v", execDir & ":/app:ro",
    "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=" & spec.tmpfsSize,
    "--tmpfs", "/run:rw,nosuid,nodev,noexec,size=1m"
  ])
  for item in spec.env:
    args.add("-e")
    args.add(item)
  args.add(spec.image)
  args.add("sh")
  args.add("-c")
  args.add(spec.command)

  "docker " & args.map(shellQuote).join(" ")

proc cleanupContainer(containerName: string) =
  if containerName.len > 0:
    discard execCmdEx("docker rm -f " & shellQuote(containerName))

proc cleanupStaleSandboxes() =
  discard execCmdEx("docker ps -aq --filter name=^/nim_pg_ | xargs -r docker rm -f")
  createDir(SandboxRoot)
  setFilePermissions(SandboxRoot, {fpUserRead, fpUserWrite, fpUserExec})
  for kind, path in walkDir(SandboxRoot):
    if kind == pcDir and splitFile(path).name.startsWith("nim_pg_"):
      try:
        setFilePermissions(path, {fpUserRead, fpUserWrite, fpUserExec})
        removeDir(path)
      except CatchableError:
        echo "stale sandbox cleanup error: ", getCurrentExceptionMsg()

proc executeCode(code, language: string): RunResult {.gcsafe.} =
  if code.len > MaxCodeBytes:
    result.output = "[Error] Code exceeds 64KB limit."
    result.exitCode = 2
    return

  if not tryAcquireExecution():
    result.output = "[Error] Sandbox is busy. Try again shortly."
    result.exitCode = 429
    return

  if not sandboxRuntimeAvailable():
    result.output = "[Error] Sandbox runtime is not available. Check SANDBOX_RUNTIME and Docker runtimes."
    result.exitCode = 503
    releaseExecution()
    return

  let spec = getSpec(language)
  let token = randomHex(8)
  let execDir = absolutePath(SandboxRoot / ("nim_pg_" & token))
  let containerName = "nim_pg_" & token

  try:
    createDir(SandboxRoot)
    setFilePermissions(SandboxRoot, {fpUserRead, fpUserWrite, fpUserExec})
    createDir(execDir)
    let sourceFile = execDir / spec.fileName
    writeFile(sourceFile, code)
    setFilePermissions(sourceFile, {fpUserRead, fpGroupRead, fpOthersRead})
    setFilePermissions(execDir, {fpUserRead, fpUserExec, fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})

    let rawCmd = dockerCommand(spec, execDir, containerName)
    let command = "set -o pipefail; timeout -k 2s " & $spec.timeoutSeconds & "s " &
      rawCmd & " 2>&1 | head -c " & $MaxOutputBytes

    let startedAt = epochTime()
    let (output, exitCode) = execCmdEx("bash -c " & shellQuote(command) & " 2>/dev/null")
    let elapsed = epochTime() - startedAt
    result.output = output
    result.exitCode = exitCode

    # 137 (SIGKILL) can mean either the timeout escalation or the cgroup OOM
    # killer; the container is already gone (--rm), so use elapsed time to
    # tell them apart.
    if exitCode == 124 or (exitCode == 125 and output.len == 0) or
        (exitCode == 137 and elapsed >= spec.timeoutSeconds.float - 0.5):
      result.output &= "\n[Error] Execution timed out (limit: " & $spec.timeoutSeconds & "s)."
    elif exitCode == 137:
      result.output &= "\n[Error] Execution was killed, most likely out of memory (limit: " & spec.memory & ")."
    elif output.len >= MaxOutputBytes:
      result.output &= "\n[Error] Output exceeded limit (64KB)."
  finally:
    cleanupContainer(containerName)
    if dirExists(execDir):
      try:
        setFilePermissions(execDir, {fpUserRead, fpUserWrite, fpUserExec})
        removeDir(execDir)
      except CatchableError:
        echo "sandbox cleanup error: ", getCurrentExceptionMsg()
    releaseExecution()

proc toMsg(r: RunResult): RunResultMsg =
  result.exitCode = r.exitCode.int32
  let n = min(r.output.len, result.output.len)
  result.outputLen = n.int32
  if n > 0:
    copyMem(addr result.output[0], unsafeAddr r.output[0], n)

proc toRunResult(m: RunResultMsg): RunResult =
  result.exitCode = m.exitCode.int
  result.output = newString(m.outputLen)
  if m.outputLen > 0:
    copyMem(addr result.output[0], unsafeAddr m.output[0], m.outputLen)

proc runCodeWorker(code, language: string): RunResultMsg {.gcsafe, raises: [].} =
  try:
    result = toMsg(executeCode(code, language))
  except CatchableError:
    result = toMsg(RunResult(output: "[Error] Internal execution failure.", exitCode: 1))

proc parsePayload(body: string; code, language: var string): bool =
  try:
    let bodyNode = parseJson(body)
    code = bodyNode{"code"}.getStr()
    language = bodyNode{"language"}.getStr()
    result = code.len > 0 and isAllowedLanguage(language)
  except CatchableError:
    result = false

proc index(ctx: Context) {.async.} =
  {.cast(gcsafe).}:
    resp htmlResponse(indexHtml, headers = securityHeaders(includeCsp = true))

proc health(ctx: Context) {.async.} =
  var allowed: bool
  {.cast(gcsafe).}:
    allowed = allowRequest(ctx, "health", HealthRequestsPerMinute)
  if not allowed:
    var response = errorResponse("Too many health requests", Http429)
    response.headers["Retry-After"] = "60"
    resp response
    return

  let runtime = sandboxRuntime()
  let runtimeReady = sandboxRuntimeAvailable()
  resp jsonResponse(%*{
    "ok": runtimeReady,
    "sandboxRuntime": runtime,
    "sandboxRuntimeReady": runtimeReady,
    "maxCodeBytes": MaxCodeBytes,
    "maxOutputBytes": MaxOutputBytes,
    "maxConcurrentExecutions": MaxConcurrentExecutions
  }, if runtimeReady: Http200 else: Http503, headers = securityHeaders())

proc getSnippet(ctx: Context) {.async.} =
  var allowed: bool
  {.cast(gcsafe).}:
    allowed = allowRequest(ctx, "snippet-read", SnippetReadRequestsPerMinute)
  if not allowed:
    var response = errorResponse("Too many snippet requests", Http429)
    response.headers["Retry-After"] = "60"
    resp response
    return

  let id = ctx.getPathParams("id")
  if not isHexId(id):
    resp errorResponse("Snippet not found", Http404)
    return

  acquire(dbLock)
  try:
    let db = open(DbPath, "", "", "")
    try:
      let cutoff = epochTime().int - SnippetTtlDays * 24 * 60 * 60
      let row = db.getRow(sql"SELECT code, language FROM snippets WHERE id = ? AND (created_at = 0 OR created_at >= ?)", id, cutoff)
      if row[0] == "":
        resp errorResponse("Snippet not found", Http404)
      else:
        resp jsonResponse(%*{"code": row[0], "language": row[1]}, headers = securityHeaders())
    finally:
      db.close()
  finally:
    release(dbLock)

proc saveSnippet(ctx: Context) {.async.} =
  if not wantsJson(ctx):
    resp errorResponse("Content-Type must be application/json", Http415)
    return
  var allowed: bool
  {.cast(gcsafe).}:
    allowed = allowRequest(ctx, "snippet", SnippetRequestsPerMinute)
  if not allowed:
    var response = errorResponse("Too many snippet requests", Http429)
    response.headers["Retry-After"] = "60"
    resp response
    return

  var code, language: string
  if not parsePayload(ctx.request.body, code, language):
    resp errorResponse("Invalid request", Http400)
    return
  if code.len > MaxCodeBytes:
    resp errorResponse("Code exceeds 64KB limit", Http413)
    return

  acquire(dbLock)
  try:
    let db = open(DbPath, "", "", "")
    try:
      let stored = db.getValue(sql"SELECT COUNT(*) FROM snippets")
      if stored.len > 0 and stored.parseInt() >= MaxStoredSnippets:
        resp errorResponse("Snippet storage is full. Try again later.", Http503)
        return
      for attempt in 0 ..< 5:
        let id = randomHex(16)
        try:
          db.exec(sql"INSERT INTO snippets (id, code, language, created_at) VALUES (?, ?, ?, ?)", id, code, language, epochTime().int)
          resp jsonResponse(%*{"id": id}, headers = securityHeaders())
          return
        except DbError:
          if attempt == 4:
            raise
      resp errorResponse("Error saving snippet", Http500)
    finally:
      db.close()
  except CatchableError:
    resp errorResponse("Error saving snippet", Http500)
  finally:
    release(dbLock)

proc purgeExpiredSnippets() {.gcsafe.} =
  {.cast(gcsafe).}:
    acquire(dbLock)
    try:
      let db = open(DbPath, "", "", "")
      try:
        db.exec(sql"DELETE FROM snippets WHERE created_at > 0 AND created_at < ?", epochTime().int - SnippetTtlDays * 24 * 60 * 60)
      finally:
        db.close()
    finally:
      release(dbLock)

proc maintenanceLoop() {.async.} =
  while true:
    await sleepAsync(SnippetPurgeIntervalSeconds * 1000)
    try:
      purgeExpiredSnippets()
    except CatchableError:
      echo "snippet purge error: ", getCurrentExceptionMsg()

proc runCode(ctx: Context) {.async.} =
  if not wantsJson(ctx):
    resp errorResponse("Content-Type must be application/json", Http415)
    return
  var allowed: bool
  {.cast(gcsafe).}:
    allowed = allowRequest(ctx, "run", RunRequestsPerMinute)
  if not allowed:
    var response = errorResponse("Too many execution requests", Http429)
    response.headers["Retry-After"] = "60"
    resp response
    return

  var code, language: string
  if not parsePayload(ctx.request.body, code, language):
    resp errorResponse("Invalid request", Http400)
    return
  if code.len > MaxCodeBytes:
    resp errorResponse("Code exceeds 64KB limit", Http413)
    return

  try:
    var fv: Flowvar[RunResultMsg]
    {.cast(gcsafe).}:
      fv = execPool.spawn runCodeWorker(code, language)
    while not fv.isReady():
      await sleepAsync(20)
    let execResult = toRunResult(sync(fv))
    if execResult.exitCode == 429:
      var response = errorResponse(execResult.output, Http429)
      response.headers["Retry-After"] = "5"
      resp response
    elif execResult.exitCode == 503:
      resp errorResponse(execResult.output, Http503)
    else:
      resp jsonResponse(%*{"output": execResult.output, "exitCode": execResult.exitCode}, headers = securityHeaders())
  except CatchableError:
    echo "runCode error: ", getCurrentExceptionMsg()
    resp errorResponse("Error processing request", Http500)

proc readPort(): Port =
  let raw = getEnv("PORT", "8888")
  var value: int
  try:
    value = raw.parseInt()
  except ValueError:
    quit("Invalid PORT value: " & raw, 1)
  if value < 1 or value > 65535:
    quit("PORT out of range: " & raw, 1)
  Port(value)

cleanupStaleSandboxes()
initDb()
indexHtml = readFile("public/index.html")
cspHeader = buildCsp(indexHtml)
execPool = Taskpool.new(numThreads = MaxConcurrentExecutions + 2)

let settings = newSettings(address = "127.0.0.1", port = readPort(), debug = false)
var app = newApp(settings = settings)
app.addRoute("/", index, HttpGet)
app.addRoute("/healthz", health, HttpGet)
app.addRoute("/run", runCode, HttpPost)
app.addRoute("/snippet", saveSnippet, HttpPost)
app.addRoute("/snippet/{id}", getSnippet, HttpGet)
asyncCheck maintenanceLoop()
app.run()
