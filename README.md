# Yopass Java

A Java implementation of [Yopass](https://github.com/jhaals/yopass) — a web application for sharing secrets securely.

## Overview

Secrets are encrypted client-side using the Web Crypto API (AES-GCM) before being sent to the server. The server never sees plaintext secrets or decryption keys (zero-knowledge architecture).

## Tech Stack

- **Java 11**
- **Spark** (web framework)
- **Memcached** (secret storage via xmemcached client)
- **Logback** (logging)
- **Maven** (build tool)

## Building

```bash
mvn clean package
```

## Running

```bash
java -jar target/yopass-java-1.0.0.jar
```

The application requires a Memcached instance to be available. Configure the connection via environment variables or defaults.

## Features

- Zero-knowledge architecture: encryption/decryption happens client-side (AES-GCM)
- One-time secrets: automatically deleted after retrieval
- Configurable expiration (1 hour, 1 day, 1 week)
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- IP-based rate limiting (30 requests/minute)
- Health check endpoint (`/healthz`)
- Graceful shutdown with resource cleanup
- Singleton Memcached connection pool (binary protocol)

## Configuration

| Environment Variable | Description                  | Default          |
|----------------------|------------------------------|------------------|
| `PORT`               | Server port (cloud priority) | `4567`           |
| `YP_PORT`           | Server port (fallback)       | `4567`           |
| `YP_MEMCACHED`      | Memcached address            | `localhost:11211`|

## Limitations

- Does not support SMS providers
- Rate limiter is in-memory (not distributed); suitable for single-instance deployments

## Disclaimer

This project started as a learning exercise but has been developed to production-ready standards, including input validation, security hardening, proper error handling, and structured logging. Deploy at your discretion following your own security review.