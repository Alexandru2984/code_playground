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

Rate limiting is keyed to the `X-Real-IP` header only. Nginx must set `proxy_set_header X-Real-IP $remote_addr;` on the proxied location (combined with Cloudflare `set_real_ip_from` rules so `$remote_addr` is the real client address). Client-supplied `X-Forwarded-For` is deliberately ignored. All endpoints are rate limited, snippet storage is capped at 20k rows, and expired snippets are purged hourly.

Known limitation: the service still needs Docker access through the dedicated `nimplayground` system user. For stronger isolation, split execution into a separate runner VM/VPS or a minimal local runner process that owns Docker access.

## Runtime State

Runtime files are intentionally ignored by Git:

- `data/snippets.db`
- `sandbox/`
- local build binaries
- local `.env` files

The service only reads and writes `data/snippets.db`; a legacy `snippets.db` at the repository root is ignored and can be deleted.

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

Pre-pull official runtime images before production tests or deploys. Pulling
during `/run` counts against each language timeout and can make the first user
request fail even when the sandbox itself is healthy:

```sh
docker pull python:3.13-alpine
docker pull node:24-alpine
docker pull ruby:3.4-alpine
docker pull php:8.4-cli-alpine
docker pull perl:5.40-slim
docker pull gcc:14
docker pull rust:1-alpine
docker pull golang:1.25-alpine
docker pull eclipse-temurin:25-jdk-alpine
docker pull nimlang/nim:2.2.4-alpine
```

## Deployment Notes

The current production service is managed by systemd as `nimplayground`.

Common checks:

```sh
systemctl status nimplayground
journalctl -u nimplayground -n 100 --no-pager
docker ps -a --filter name=nim_pg_
```

The Docker daemon must expose a `runsc` runtime. On Ubuntu hosts with the
`runsc` package installed, `/etc/docker/daemon.json` should keep the normal
default runtime and add only the sandbox runtime:

```json
{
  "ipv6": true,
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": ["--network=none"]
    }
  }
}
```

Reload Docker after editing the daemon config:

```sh
sudo kill -SIGHUP "$(pidof dockerd)"
docker info --format '{{json .Runtimes}}'
docker run --rm --runtime runsc --network none --read-only alpine:latest /bin/true
```

The `runtimeArgs` entry forces gVisor networking off at the runtime layer. The
application also passes Docker `--network none`; both controls should remain in
place for public code execution.

Nginx owns the public security headers. The app also sends the same headers for
direct localhost smoke tests, so the proxied vhost should hide upstream copies
before adding the canonical public values:

```nginx
proxy_hide_header X-Content-Type-Options;
proxy_hide_header X-Frame-Options;
proxy_hide_header Referrer-Policy;
proxy_hide_header Permissions-Policy;
proxy_hide_header Content-Security-Policy;
```

The HTTP-to-HTTPS redirect server should also set the same public security
headers explicitly. Otherwise it inherits the generic `http {}` defaults from
`/etc/nginx/nginx.conf`, which can produce different policies on port 80 than
on the HTTPS vhost.

After changing `public/index.html`, recalculate the inline script/style hashes and update the Nginx CSP before reloading Nginx.

Before restarting production, smoke-test the new binary on a temporary port:

```sh
nim c -d:release -d:websocketx src/nimplayground.nim
PORT=8898 SANDBOX_RUNTIME=runsc ./src/nimplayground
curl -sS http://127.0.0.1:8898/healthz
curl -sS -X POST http://127.0.0.1:8898/run \
  -H 'Content-Type: application/json' \
  --data '{"code":"print(\"hello runsc\")","language":"python"}'
```

## Configuration

The service reads all configuration from environment variables. The `PORT` variable (default `8888`) must be provided by the environment — set it via systemd `EnvironmentFile=` or by exporting it before running locally:

```sh
export PORT=8888
./nimplayground
```

The `.env` file at the repository root is loaded automatically by systemd via `EnvironmentFile=` in the unit file. It is **not** read by the application itself.
