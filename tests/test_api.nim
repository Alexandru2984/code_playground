import unittest
import httpclient
import json
import os
import strutils

suite "Code Playground - Security & Execution Tests":
  setup:
    let client = newHttpClient()
    let baseUrl = "http://127.0.0.1:8888"

  test "GET / returns HTML frontend":
    let res = client.request(baseUrl & "/", HttpGet)
    check res.code == Http200
    check res.body.contains("Code Playground")

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

  test "POST /snippet saves code and GET /snippet/{id} retrieves it":
    let body = %*{
      "code": "print('Saved snippet')",
      "language": "python"
    }
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let postRes = client.request(baseUrl & "/snippet", HttpPost, body = $body)
    check postRes.code == Http200
    let id = parseJson(postRes.body){"id"}.getStr()
    check id.len == 6

    let getRes = client.request(baseUrl & "/snippet/" & id, HttpGet)
    check getRes.code == Http200
    let retrieved = parseJson(getRes.body)
    check retrieved{"code"}.getStr() == "print('Saved snippet')"
    check retrieved{"language"}.getStr() == "python"

  test "GET /snippet/invalid returns 404":
    let getRes = client.request(baseUrl & "/snippet/invalid999", HttpGet)
    check getRes.code == Http404

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
