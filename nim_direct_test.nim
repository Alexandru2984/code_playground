import osproc, os
let execDir = getTempDir() / "nim_pg_debug"
createDir(execDir)
let tmpFile = execDir / "snippet.cpp"
writeFile(tmpFile, "#include <iostream>\nint main() { std::cout << \"Secure C++\\n\"; return 0; }")
let cmd = "bash -c 'set -o pipefail; timeout -k 1s 5s docker run --rm -i --user 65534:65534 -e HOME=/tmp --cap-drop ALL --security-opt no-new-privileges -v " & execDir & ":/app:ro --tmpfs /tmp:rw,exec,size=50m --memory=\"128m\" --cpus=\"1.0\" --network none --pids-limit 64 gcc:11 sh -c \"cd /tmp && cp /app/snippet.cpp . && g++ snippet.cpp -o prog && ./prog\" 2>&1 | head -c 65536'"
let (outStr, exitCode) = execCmdEx(cmd)
echo "Output: [", outStr, "]"
echo "ExitCode: ", exitCode
