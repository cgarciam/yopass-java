# Yopass Java

A Java implementation of [Yopass](https://github.com/jhaals/yopass) — a web application for sharing secrets securely.

## Overview

Secrets are encrypted client-side using the Web Crypto API (AES-GCM 256-bit) before being sent to the server. The server never sees plaintext secrets or decryption keys (zero-knowledge architecture).

## Tech Stack

### Backend
- **Java 17**
- **Javalin 7** (web framework, includes Jetty 12)
- **Memcached** (secret storage via xmemcached client)
- **SLF4J + Logback** (structured logging)
- **Maven** (build tool with shade plugin for fat JAR)

### Frontend
- **Vue 3** (reactive UI)
- **Vue Router** (hash-based client-side routing)
- **Bootstrap 3** (styling)
- **Web Crypto API** (AES-GCM 256-bit client-side encryption)

### Testing
- **JUnit 5** (unit tests with parameterized tests)

## Project Structure

```
src/
├── main/
│   ├── java/se/jhaals/
│   │   ├── Yopass.java        # Main server, routes, security headers
│   │   ├── Memcached.java     # Singleton Memcached client wrapper
│   │   └── RateLimiter.java   # In-memory IP-based rate limiter
│   └── resources/
│       ├── logback.xml        # Logging configuration
│       └── public/            # Static frontend assets
│           ├── index.html
│           ├── js/app.js      # Vue 3 app with client-side crypto
│           ├── css/           # Bootstrap + custom styles
│           ├── fonts/         # Glyphicons
│           └── img/           # Favicon
└── test/
    └── java/se/jhaals/
        └── YopassTest.java    # Unit tests
```

## Building

```bash
mvn clean package
```

This produces a fat JAR at `target/yopass-java-1.0.0.jar` (via the Maven Shade plugin).

## Running

### Prerequisites

- **Java 17+**
- **Memcached** instance running (default: `localhost:11211`)

### Start the server

```bash
java -jar target/yopass-java-1.0.0.jar
```

The application will be available at `http://localhost:4567`.

## Features

- **Zero-knowledge architecture** — encryption/decryption happens client-side (AES-GCM 256-bit)
- **One-time secrets** — automatically deleted after retrieval (atomic get-and-delete)
- **Configurable expiration** — 1 hour, 1 day, or 1 week
- **Security headers** — CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, and more
- **IP-based rate limiting** — 30 requests/minute per IP with automatic stale-entry cleanup
- **Health check endpoint** — `GET /healthz` with Memcached connectivity verification
- **Decryption failure reporting** — client reports failed decryptions for audit logging
- **Graceful shutdown** — clean resource cleanup via shutdown hook
- **Singleton Memcached connection pool** — binary protocol, 5 connections, session healing
- **X-Forwarded-For support** — correct client IP extraction behind reverse proxies

## API Reference

### Store a secret

```
POST /v1/secret
Content-Type: application/json

{
  "secret": "<base64url-encoded ciphertext>",
  "lifetime": "1h"    // "1h", "1d", or "1w" (default: "1h")
}

→ 200 { "key": "<storage-key>", "message": "secret stored" }
```

### Retrieve a secret (one-time)

```
GET /v1/secret/{key}

→ 200 { "secret": "<ciphertext>", "message": "OK" }
→ 404 { "message": "Secret not found or already consumed" }
```

The secret is atomically deleted upon retrieval — only one request can claim it.

### Report decryption failure

```
POST /v1/secret/decryption-failure
Content-Type: application/json

{ "key": "<storage-key>" }

→ 200 { "message": "Failure recorded" }
```

### Health check

```
GET /healthz

→ 200 { "status": "ok" }
→ 503 { "status": "unhealthy", "error": "memcached unavailable" }
```

## Configuration

| Environment Variable | Description                  | Default          |
|----------------------|------------------------------|------------------|
| `PORT`               | Server port (cloud priority) | `4567`           |
| `YP_PORT`            | Server port (fallback)       | `4567`           |
| `YP_MEMCACHED`       | Memcached address            | `localhost:11211`|

Port resolution order: `PORT` → `YP_PORT` → `4567`.

## Security

### Headers (applied to all responses)

| Header                       | Value                                                  |
|------------------------------|--------------------------------------------------------|
| `X-Content-Type-Options`     | `nosniff`                                              |
| `X-Frame-Options`            | `DENY`                                                 |
| `Referrer-Policy`            | `no-referrer`                                          |
| `Content-Security-Policy`    | Restrictive policy (no inline scripts, self-only)      |
| `Permissions-Policy`         | Camera, microphone, geolocation disabled               |
| `Cache-Control`              | `no-store, no-cache, must-revalidate, private`         |
| `Strict-Transport-Security`  | `max-age=31536000; includeSubDomains`                  |
| `Cross-Origin-Resource-Policy`| `same-origin`                                         |

### Input Validation

- Content-Type enforcement (`application/json` required for POST)
- Request body size limit (150 KB)
- Secret ciphertext length limit (100,000 characters)
- Storage key format validation (22-character alphanumeric)

## Deployment (Render.com)

The project includes configuration for deploying to [Render.com](https://render.com) free tier:

- **`Dockerfile.render`** — Multi-stage build bundling yopass-java + Memcached in a single container
- **`render.yaml`** — Render Blueprint for one-click deployment
- **`entrypoint-render.sh`** — Entrypoint script that starts Memcached and the Java app with dropped privileges

Render handles TLS termination automatically. Memcached listens only on `127.0.0.1` inside the container.

```bash
# Deploy: connect your repo to Render and it auto-detects render.yaml
```

## Testing

```bash
mvn test
```

Unit tests cover:
- Lifetime/TTL resolution for all valid and invalid inputs
- Secure random key generation (length, character set, uniqueness)
- Constant values (key length, max secret length)

## Limitations

- Rate limiter is in-memory (not distributed); suitable for single-instance deployments
- Secrets are lost if Memcached is restarted (in-memory storage only)
- Render free tier spins down after 15 minutes of inactivity (~30s cold start)

## Disclaimer

This project started as a learning exercise but has been developed to production-ready standards, including input validation, security hardening, proper error handling, and structured logging. Deploy at your discretion following your own security review.