import prologue
import json
import osproc
import os
import strutils
import times
import streams
import db_connector/db_sqlite
import std/random

randomize()
let db = open("snippets.db", "", "", "")
db.exec(sql"CREATE TABLE IF NOT EXISTS snippets (id TEXT PRIMARY KEY, code TEXT, language TEXT)")

proc index(ctx: Context) {.async.} =
  let content = readFile("public/index.html")
  resp content

proc runCode(ctx: Context) {.async.} =
  var execDir = ""
  try:
    let bodyNode = parseJson(ctx.request.body)
    let code = bodyNode{"code"}.getStr()
    let language = bodyNode{"language"}.getStr()

    if language notin ["python", "javascript", "c", "cpp", "rust", "go"]:
      resp jsonResponse(%*{"message": "Unsupported language"}, Http400)
      return
    
    # Phase 2 & 3: Sandboxing and Multi-language support
    let timestamp = $epochTime()
    execDir = getTempDir() / ("nim_pg_" & timestamp.replace(".", "_"))
    createDir(execDir)
    
    var tmpFile = ""
    var cmd = ""

    if language == "python":
      tmpFile = execDir / "snippet.py"
      writeFile(tmpFile, code)
      cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --memory=\"64m\" --cpus=\"0.5\" --network none --pids-limit 64 python:3.9-alpine python /app/snippet.py 2>&1 | head -c 65536'"
    elif language == "javascript":
      tmpFile = execDir / "snippet.js"
      writeFile(tmpFile, code)
      cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --memory=\"64m\" --cpus=\"0.5\" --network none --pids-limit 64 node:18-alpine node /app/snippet.js 2>&1 | head -c 65536'"
    elif language == "c":
      tmpFile = execDir / "snippet.c"
      writeFile(tmpFile, code)
      cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=50m --memory=\"128m\" --cpus=\"1.0\" --network none --pids-limit 64 gcc:11 sh -c \"cd /tmp && cp /app/snippet.c . && gcc snippet.c -o prog && ./prog\" 2>&1 | head -c 65536'"
    elif language == "cpp":
      tmpFile = execDir / "snippet.cpp"
      writeFile(tmpFile, code)
      cmd = "bash -c 'set -o pipefail; timeout -k 1s 10s docker run --rm -i --user 65534:65534 -e HOME=/tmp --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=50m --memory=\"128m\" --cpus=\"1.0\" --network none --pids-limit 64 gcc:11 sh -c \"cd /tmp && cp /app/snippet.cpp . && g++ snippet.cpp -o prog && ./prog\" 2>&1 | head -c 65536'"
    elif language == "rust":
      tmpFile = execDir / "snippet.rs"
      writeFile(tmpFile, code)
      cmd = "bash -c 'set -o pipefail; timeout -k 1s 10s docker run --rm -i --user 65534:65534 -e HOME=/tmp --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=100m --memory=\"256m\" --cpus=\"1.0\" --network none --pids-limit 64 rust:1-alpine sh -c \"cd /tmp && cp /app/snippet.rs . && rustc snippet.rs -o prog && ./prog\" 2>&1 | head -c 65536'"
    elif language == "go":
      let tmpFile = execDir / "snippet.go"
      writeFile(tmpFile, code)
      cmd = "bash -c 'set -o pipefail; timeout -k 1s 35s docker run --rm -i --user 65534:65534 -e CGO_ENABLED=0 -e HOME=/tmp -e GOCACHE=/tmp/.cache -e GOPROXY=off -e GOSUMDB=off --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=100m --memory=\"256m\" --cpus=\"1.0\" --network none --pids-limit 256 golang:1.20-alpine sh -c \"cd /tmp && cp /app/snippet.go . && go build -o prog snippet.go && ./prog\" 2>&1 | head -c 65536'"

    let (output, exitCode) = execCmdEx(cmd)

    var finalOutput = output
    if exitCode == 124 or exitCode == 137:
      finalOutput &= "\n[Error] Execution timed out (limit: 35s)."

    resp jsonResponse(%*{"output": finalOutput, "exitCode": exitCode})
  except:
    let e = getCurrentException()
    resp jsonResponse(%*{"message": "Error processing request", "details": e.msg}, Http500)
  finally:
    if execDir != "" and dirExists(execDir):
      removeDir(execDir)

# Setup basic configuration
var portStr = "8888"
if fileExists(".env"):
  for line in lines(".env"):
    if line.startsWith("PORT="):
      portStr = line.split("=")[1].strip()

let port = portStr.parseInt().Port
let settings = newSettings(port = port)

var app = newApp(settings = settings)
proc saveSnippet(ctx: Context) {.async.} =
  try:
    let bodyNode = parseJson(ctx.request.body)
    let code = bodyNode{"code"}.getStr()
    let language = bodyNode{"language"}.getStr()

    if language notin ["python", "javascript", "c", "cpp", "rust", "go"]:
      resp jsonResponse(%*{"message": "Unsupported language"}, Http400)
      return

    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    var id = ""
    for i in 0..5:
      id.add(chars[rand(chars.len - 1)])

    db.exec(sql"INSERT INTO snippets (id, code, language) VALUES (?, ?, ?)", id, code, language)
    resp jsonResponse(%*{"id": id})
  except:
    let e = getCurrentException()
    resp jsonResponse(%*{"message": "Error saving snippet", "details": e.msg}, Http500)

proc getSnippet(ctx: Context) {.async.} =
  let id = ctx.getPathParams("id")
  let row = db.getRow(sql"SELECT code, language FROM snippets WHERE id = ?", id)
  if row[0] == "":
    resp jsonResponse(%*{"message": "Snippet not found"}, Http404)
  else:
    resp jsonResponse(%*{"code": row[0], "language": row[1]})

app.addRoute("/", index, HttpGet)
app.addRoute("/run", runCode, HttpPost)
app.addRoute("/snippet", saveSnippet, HttpPost)
import prologue/websocket

proc wsRunCode(ctx: Context) {.async.} =
  var ws = await newWebSocket(ctx)
  let msgData = await ws.receiveStrPacket()
  if msgData == "":
    ws.close()
    return
    
  let bodyNode = parseJson(msgData)
  let code = bodyNode{"code"}.getStr()
  let language = bodyNode{"language"}.getStr()
  
  if language notin ["python", "javascript", "c", "cpp", "rust", "go"]:
    await ws.send("Unsupported language")
    ws.close()
    return
    
  let timestamp = $epochTime()
  var execDir = getTempDir() / ("nim_pg_ws_" & timestamp.replace(".", "_"))
  createDir(execDir)
  
  var cmd = ""
  if language == "python":
    let tmpFile = execDir / "snippet.py"
    writeFile(tmpFile, code)
    cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --memory=\"64m\" --cpus=\"0.5\" --network none --pids-limit 64 python:3.9-alpine python -u /app/snippet.py 2>&1 | head -c 65536'"
  elif language == "javascript":
    let tmpFile = execDir / "snippet.js"
    writeFile(tmpFile, code)
    cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --memory=\"64m\" --cpus=\"0.5\" --network none --pids-limit 64 node:18-alpine node /app/snippet.js 2>&1 | head -c 65536'"
  elif language == "c":
    let tmpFile = execDir / "snippet.c"
    writeFile(tmpFile, code)
    cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=50m --memory=\"128m\" --cpus=\"1.0\" --network none --pids-limit 64 gcc:11 sh -c \"cd /tmp && cp /app/snippet.c . && gcc snippet.c -o prog && stdbuf -i0 -o0 -e0 ./prog\" 2>&1 | head -c 65536'"
  elif language == "cpp":
    let tmpFile = execDir / "snippet.cpp"
    writeFile(tmpFile, code)
    cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 -e HOME=/tmp --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=50m --memory=\"128m\" --cpus=\"1.0\" --network none --pids-limit 64 gcc:11 sh -c \"cd /tmp && cp /app/snippet.cpp . && g++ snippet.cpp -o prog && stdbuf -i0 -o0 -e0 ./prog\" 2>&1 | head -c 65536'"
  elif language == "rust":
    let tmpFile = execDir / "snippet.rs"
    writeFile(tmpFile, code)
    cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 -e HOME=/tmp --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=100m --memory=\"256m\" --cpus=\"1.0\" --network none --pids-limit 64 rust:1-alpine sh -c \"cd /tmp && cp /app/snippet.rs . && rustc snippet.rs -o prog && stdbuf -i0 -o0 -e0 ./prog\" 2>&1 | head -c 65536'"
  elif language == "go":
    let tmpFile = execDir / "snippet.go"
    writeFile(tmpFile, code)
    cmd = "bash -c 'set -o pipefail; timeout -k 1s 10s docker run --rm -i --user 65534:65534 -e CGO_ENABLED=0 -e HOME=/tmp -e GOCACHE=/tmp/.cache -e GOPROXY=off -e GOSUMDB=off --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=100m --memory=\"256m\" --cpus=\"1.0\" --network none --pids-limit 256 golang:1.20-alpine sh -c \"cd /tmp && cp /app/snippet.go . && go build -o prog snippet.go && ./prog\" 2>&1 | head -c 65536'"
    
  var p = startProcess("bash", args = ["-c", cmd], options = {poUsePath, poStdErrToStdOut})
  var stream = p.outputStream()
  var buf = newString(512)
  var totalSent = 0
  
  while true:
    let bytesRead = stream.readData(addr buf[0], 512)
    if bytesRead > 0:
      totalSent += bytesRead
      if totalSent > 65536:
        await ws.send("\n[Error] Output exceeded limit (64KB).")
        p.kill()
        break
      await ws.send(buf[0..<bytesRead])
    
    if not p.running():
      let extraRead = stream.readData(addr buf[0], 512)
      if extraRead > 0:
        await ws.send(buf[0..<extraRead])
      break
  
  let exitCode = p.peekExitCode()
  if exitCode == 124 or exitCode == 137:
    await ws.send("\n[Error] Execution timed out (limit: 35s).")
  
  p.close()
  removeDir(execDir)
  ws.close()

app.addRoute("/snippet/{id}", getSnippet, HttpGet)
app.addRoute("/ws/run", wsRunCode, HttpGet)
app.run()
