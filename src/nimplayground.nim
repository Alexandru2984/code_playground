import prologue
import json
import osproc
import os
import strutils
import times
import db_connector/db_sqlite
import std/[locks, sequtils, sysrand]

const
  AllowedLanguages = [
    "python", "javascript", "ruby", "php", "lua", "perl",
    "c", "cpp", "rust", "go", "java", "nim",
    "python-ds", "cpp-drogon"
  ]
  MaxCodeBytes = 65536
  MaxOutputBytes = 65536
  MaxConcurrentExecutions = 2
  SnippetTtlDays = 30
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

var
  execLock: Lock
  activeExecutions: int
  dbLock: Lock

initLock(execLock)
initLock(dbLock)

proc initDb() =
  acquire(dbLock)
  try:
    createDir(DataRoot)
    if fileExists("snippets.db") and not fileExists(DbPath):
      copyFile("snippets.db", DbPath)
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
      try:
        db.exec(sql"ALTER TABLE snippets ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")
      except DbError:
        discard
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

proc shellQuote(value: string): string =
  "'" & value.replace("'", "'\\''") & "'"

proc sandboxUser(): string =
  getEnv("SANDBOX_UID", "997") & ":" & getEnv("SANDBOX_GID", "986")

proc sandboxRuntime(): string =
  getEnv("SANDBOX_RUNTIME", "runsc").strip()

proc tryAcquireExecution(): bool =
  acquire(execLock)
  if activeExecutions >= MaxConcurrentExecutions:
    release(execLock)
    return false
  inc activeExecutions
  release(execLock)
  true

proc releaseExecution() =
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

proc executeCode(code, language: string): RunResult =
  if code.len > MaxCodeBytes:
    result.output = "[Error] Code exceeds 64KB limit."
    result.exitCode = 2
    return

  if not tryAcquireExecution():
    result.output = "[Error] Sandbox is busy. Try again shortly."
    result.exitCode = 429
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
    setFilePermissions(sourceFile, {fpUserRead})
    setFilePermissions(execDir, {fpUserRead, fpUserExec})

    let rawCmd = dockerCommand(spec, execDir, containerName)
    let command = "set -o pipefail; timeout -k 2s " & $spec.timeoutSeconds & "s " &
      rawCmd & " 2>&1 | head -c " & $MaxOutputBytes

    let (output, exitCode) = execCmdEx("bash -c " & shellQuote(command) & " 2>/dev/null")
    result.output = output
    result.exitCode = exitCode

    if exitCode == 124 or exitCode == 137:
      result.output &= "\n[Error] Execution timed out (limit: " & $spec.timeoutSeconds & "s)."
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

proc parsePayload(body: string; code, language: var string): bool =
  try:
    let bodyNode = parseJson(body)
    code = bodyNode{"code"}.getStr()
    language = bodyNode{"language"}.getStr()
    result = code.len > 0 and isAllowedLanguage(language)
  except CatchableError:
    result = false

proc index(ctx: Context) {.async.} =
  resp readFile("public/index.html")

proc getSnippet(ctx: Context) {.async.} =
  let id = ctx.getPathParams("id")
  if id.len != 32:
    resp jsonResponse(%*{"message": "Snippet not found"}, Http404)
    return

  acquire(dbLock)
  try:
    let db = open(DbPath, "", "", "")
    try:
      let cutoff = epochTime().int - SnippetTtlDays * 24 * 60 * 60
      let row = db.getRow(sql"SELECT code, language FROM snippets WHERE id = ? AND (created_at = 0 OR created_at >= ?)", id, cutoff)
      if row[0] == "":
        resp jsonResponse(%*{"message": "Snippet not found"}, Http404)
      else:
        resp jsonResponse(%*{"code": row[0], "language": row[1]})
    finally:
      db.close()
  finally:
    release(dbLock)

proc saveSnippet(ctx: Context) {.async.} =
  var code, language: string
  if not parsePayload(ctx.request.body, code, language):
    resp jsonResponse(%*{"message": "Invalid request"}, Http400)
    return
  if code.len > MaxCodeBytes:
    resp jsonResponse(%*{"message": "Code exceeds 64KB limit"}, Http413)
    return

  acquire(dbLock)
  try:
    let db = open(DbPath, "", "", "")
    try:
      for attempt in 0 ..< 5:
        let id = randomHex(16)
        try:
          db.exec(sql"INSERT INTO snippets (id, code, language, created_at) VALUES (?, ?, ?, ?)", id, code, language, epochTime().int)
          resp jsonResponse(%*{"id": id})
          return
        except DbError:
          if attempt == 4:
            raise
      resp jsonResponse(%*{"message": "Error saving snippet"}, Http500)
    finally:
      db.close()
  except CatchableError:
    resp jsonResponse(%*{"message": "Error saving snippet"}, Http500)
  finally:
    release(dbLock)

proc runCode(ctx: Context) {.async.} =
  var code, language: string
  if not parsePayload(ctx.request.body, code, language):
    resp jsonResponse(%*{"message": "Invalid request"}, Http400)
    return
  if code.len > MaxCodeBytes:
    resp jsonResponse(%*{"message": "Code exceeds 64KB limit"}, Http413)
    return

  try:
    let result = executeCode(code, language)
    if result.exitCode == 429:
      resp jsonResponse(%*{"message": result.output}, Http429)
    else:
      resp jsonResponse(%*{"output": result.output, "exitCode": result.exitCode})
  except CatchableError:
    echo "runCode error: ", getCurrentExceptionMsg()
    resp jsonResponse(%*{"message": "Error processing request"}, Http500)

proc readPort(): Port =
  var portStr = getEnv("PORT", "8888")
  try:
    if fileExists(".env"):
      for line in lines(".env"):
        if line.startsWith("PORT="):
          portStr = line.split("=", maxsplit = 1)[1].strip()
  except CatchableError:
    discard
  portStr.parseInt().Port

cleanupStaleSandboxes()
initDb()

let settings = newSettings(address = "127.0.0.1", port = readPort(), debug = false)
var app = newApp(settings = settings)
app.addRoute("/", index, HttpGet)
app.addRoute("/run", runCode, HttpPost)
app.addRoute("/snippet", saveSnippet, HttpPost)
app.addRoute("/snippet/{id}", getSnippet, HttpGet)
app.run()
