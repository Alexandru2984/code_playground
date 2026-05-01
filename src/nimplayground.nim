import prologue
import json
import osproc
import os
import strutils
import times

proc index(ctx: Context) {.async.} =
  let content = readFile("public/index.html")
  resp content

proc runCode(ctx: Context) {.async.} =
  var execDir = ""
  try:
    let bodyNode = parseJson(ctx.request.body)
    let code = bodyNode{"code"}.getStr()
    let language = bodyNode{"language"}.getStr()

    if language notin ["python", "javascript", "c"]:
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
      cmd = "timeout 5s docker run --rm -v " & execDir & ":/app:ro --memory=\"64m\" --cpus=\"0.5\" --network none --pids-limit 64 python:3.9-alpine python /app/snippet.py"
    elif language == "javascript":
      tmpFile = execDir / "snippet.js"
      writeFile(tmpFile, code)
      cmd = "timeout 5s docker run --rm -v " & execDir & ":/app:ro --memory=\"64m\" --cpus=\"0.5\" --network none --pids-limit 64 node:18-alpine node /app/snippet.js"
    elif language == "c":
      tmpFile = execDir / "snippet.c"
      writeFile(tmpFile, code)
      # For C, mount read-write so GCC can output the binary, then execute it
      cmd = "timeout 5s docker run --rm -v " & execDir & ":/app:rw --memory=\"128m\" --cpus=\"1.0\" --network none --pids-limit 64 gcc:11 sh -c \"cd /app && gcc snippet.c -o prog && ./prog\""

    let (output, exitCode) = execCmdEx(cmd)

    var finalOutput = output
    if exitCode == 124:
      finalOutput &= "\n[Error] Execution timed out (limit: 5s)."

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
app.addRoute("/", index, HttpGet)
app.addRoute("/run", runCode, HttpPost)
app.run()
