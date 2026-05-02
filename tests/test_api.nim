import unittest
import httpclient
import json
import os
import osproc
import strutils

suite "Code Playground - Security & Execution Tests":
  setup:
    let client = newHttpClient()
    let baseUrl = "http://127.0.0.1:8888"

  test "GET / returns HTML frontend":
    let res = client.request(baseUrl & "/", HttpGet)
    check res.code == Http200
    check res.body.contains("Code Playground")
    check res.body.contains("fetch('/run'")
    check not res.body.contains("new WebSocket")

  test "GET /ws/run is not exposed":
    let res = client.request(baseUrl & "/ws/run", HttpGet)
    check res.code == Http404

  test "POST /run executes basic Python code":
    let body = %*{
      "code": "print('Secure Execution Working')",
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    let jsonRes = parseJson(res.body)
    check jsonRes{"output"}.getStr().contains("Secure Execution Working")
    check jsonRes{"exitCode"}.getInt() == 0

  test "POST /run executes JavaScript code":
    let body = %*{
      "code": "console.log('Secure JavaScript')",
      "language": "javascript"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure JavaScript")

  test "POST /run executes Ruby code":
    let body = %*{
      "code": "puts 'Secure Ruby'",
      "language": "ruby"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Ruby")

  test "POST /run executes PHP code":
    let body = %*{
      "code": "<?php echo \"Secure PHP\\n\";",
      "language": "php"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure PHP")

  test "POST /run executes Lua code":
    let body = %*{
      "code": "print('Secure Lua')",
      "language": "lua"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Lua")

  test "POST /run executes Perl code":
    let body = %*{
      "code": "print \"Secure Perl\\n\";",
      "language": "perl"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Perl")

  test "POST /run rejects unsupported languages":
    let body = %*{
      "code": "print('nope')",
      "language": "bash"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http400

  test "POST /run rejects code over 64KB":
    let body = %*{
      "code": "A".repeat(65537),
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http413

  test "POST /run limits output (Anti-OOM) to ~65KB":
    let body = %*{
      "code": "print('A' * 150000)", # attempt to print 150KB
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    let jsonRes = parseJson(res.body)
    # Output must be truncated around 65536 bytes
    check jsonRes{"output"}.getStr().len <= 66000 

  test "POST /run kills infinite loops (Timeout)":
    let body = %*{
      "code": "while True: pass",
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    let jsonRes = parseJson(res.body)
    check jsonRes{"exitCode"}.getInt() != 0
    check jsonRes{"output"}.getStr().contains("Execution timed out")

  test "POST /run blocks outbound network":
    let body = %*{
      "code": "import socket\ns = socket.socket()\ns.settimeout(1)\ntry:\n    s.connect(('1.1.1.1', 53))\n    print('NETWORK_OPEN')\nexcept OSError:\n    print('NETWORK_BLOCKED')",
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    let output = parseJson(res.body){"output"}.getStr()
    check output.contains("NETWORK_BLOCKED")
    check not output.contains("NETWORK_OPEN")

  test "POST /run keeps root filesystem read-only and tmp writable":
    let body = %*{
      "code": "open('/tmp/write-ok', 'w').write('ok')\ntry:\n    open('/root-write-blocked', 'w').write('bad')\n    print('ROOT_WRITABLE')\nexcept OSError:\n    print('ROOT_READ_ONLY')",
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    let output = parseJson(res.body){"output"}.getStr()
    check output.contains("ROOT_READ_ONLY")
    check not output.contains("ROOT_WRITABLE")

  test "POST /run containers use runsc and hardened Docker options":
    let body = """{"code":"import time\ntime.sleep(5)\nprint('runtime-visible')","language":"python"}"""
    let p = startProcess("curl", args = [
      "-s", "--max-time", "15",
      "-X", "POST", baseUrl & "/run",
      "-H", "Content-Type: application/json",
      "--data", body
    ], options = {poUsePath, poStdErrToStdOut})
    sleep(1200)
    let (inspectOut, inspectCode) = execCmdEx("docker ps -q --filter name=nim_pg_ | xargs -r docker inspect --format '{{.HostConfig.Runtime}} {{.HostConfig.NetworkMode}} {{range .HostConfig.SecurityOpt}}{{.}} {{end}}'")
    check inspectCode == 0
    check inspectOut.contains("runsc")
    check inspectOut.contains("none")
    check inspectOut.contains("no-new-privileges")
    check inspectOut.contains("apparmor=docker-default")
    if p.running():
      discard p.waitForExit()
    p.close()

  test "POST /run cleans up sandbox containers":
    let (containers, exitCode) = execCmdEx("docker ps -a --filter name=nim_pg_ --format '{{.ID}}'")
    check exitCode == 0
    check containers.strip() == ""

  test "POST /snippet saves code and GET /snippet/{id} retrieves it":
    let body = %*{
      "code": "print('Saved snippet')",
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let postRes = client.request(baseUrl & "/snippet", HttpPost, body = $body)
    check postRes.code == Http200
    let id = parseJson(postRes.body){"id"}.getStr()
    check id.len == 32

    let getRes = client.request(baseUrl & "/snippet/" & id, HttpGet)
    check getRes.code == Http200
    let retrieved = parseJson(getRes.body)
    check retrieved{"code"}.getStr() == "print('Saved snippet')"
    check retrieved{"language"}.getStr() == "python"

  test "GET /snippet/invalid returns 404":
    let getRes = client.request(baseUrl & "/snippet/" & "0".repeat(32), HttpGet)
    check getRes.code == Http404

  test "POST /snippet rejects code over 64KB":
    let body = %*{
      "code": "A".repeat(65537),
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/snippet", HttpPost, body = $body)
    check res.code == Http413

  test "POST /run executes C++ code":
    let body = %*{
      "code": "#include <iostream>\nint main() { std::cout << \"Secure C++\\n\"; return 0; }",
      "language": "cpp"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure C++")

  test "POST /run executes Rust code":
    let body = %*{
      "code": "fn main() { println!(\"Secure Rust\"); }",
      "language": "rust"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Rust")

  test "POST /run executes Go code":
    let body = %*{
      "code": "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"Secure Go\") }",
      "language": "go"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Go")

  test "POST /run executes Java code":
    let body = %*{
      "code": "public class Snippet { public static void main(String[] args) { System.out.println(\"Secure Java\"); } }",
      "language": "java"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Java")

  test "POST /run executes Nim code":
    let body = %*{
      "code": "echo \"Secure Nim\"",
      "language": "nim"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Nim")

  test "POST /run executes pre-baked Python Data Science code (Numpy)":
    let body = %*{
      "code": "import numpy as np\nprint(f\"Numpy {np.array([1]).sum()}\")",
      "language": "python-ds"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Numpy 1")

  test "POST /run executes pre-baked C++ Drogon Framework code":
    let body = %*{
      "code": "#include <drogon/drogon.h>\n#include <iostream>\nint main() { std::cout << \"Secure Drogon\\n\"; return 0; }",
      "language": "cpp-drogon"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let res = client.request(baseUrl & "/run", HttpPost, body = $body)
    check res.code == Http200
    check parseJson(res.body){"output"}.getStr().contains("Secure Drogon")
