# Nim Live Code Playground

A small production-deployed code playground for `nim.micutu.com`, built with Nim and Prologue.

The service accepts short snippets, runs them in isolated Docker containers through gVisor `runsc`, and returns bounded output. It is designed for hobby/public use with a conservative sandbox profile, not for executing trusted private workloads.

## Supported Languages

- Python 3.13
- JavaScript / Node.js 24
- Ruby 3.4
- PHP 8.4
- Lua 5.4
- Perl 5.40
- C / GCC 14
- C++ / GCC 14
- Rust
- Go 1.25
- Java 25
- Nim 2.2
- Python DS image with NumPy
- C++ Drogon image

## Security Model

Each run uses a fresh `nim_pg_*` container with:

- gVisor `runsc` runtime
- no outbound network
- read-only root filesystem
- source mounted read-only
- tmpfs for `/tmp` and `/run`
- dropped Linux capabilities
- `no-new-privileges`
- AppArmor `docker-default`
- memory, CPU, PID, file descriptor, timeout, input, and output limits
- deterministic cleanup of containers and sandbox directories

The web process itself binds to `127.0.0.1` and is intended to be exposed through Nginx/Cloudflare only. On this VPS, Nginx also enforces request limits, security headers, CSP, HSTS, and origin-guard checks for Cloudflare traffic.

Known limitation: the service still needs Docker access through the dedicated `nimplayground` system user. For stronger isolation, split execution into a separate runner VM/VPS or a minimal local runner process that owns Docker access.

## Runtime State

Runtime files are intentionally ignored by Git:

- `data/snippets.db`
- `sandbox/`
- local build binaries
- local `.env` files

Legacy `snippets.db` at the repository root should not be used by the running service; production uses `data/snippets.db`.

## Development

Build the app:

```sh
nimble build -d:release
```

Run the API/security test suite against the local production listener:

```sh
nim c -r -d:release -d:websocketx tests/test_api.nim
```

Build local helper images:

```sh
docker build -t python-ds -f Dockerfile.python-ds .
docker build -t cpp-drogon -f Dockerfile.cpp-drogon .
docker build -t lua-playground -f Dockerfile.lua .
```

## Deployment Notes

The current production service is managed by systemd as `nimplayground`.

Common checks:

```sh
systemctl status nimplayground
journalctl -u nimplayground -n 100 --no-pager
docker ps -a --filter name=nim_pg_
```

After changing `public/index.html`, recalculate the inline script/style hashes and update the Nginx CSP before reloading Nginx.
