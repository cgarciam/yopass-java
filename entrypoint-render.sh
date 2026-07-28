#!/bin/sh
# All-in-one entrypoint: starts Memcached and yopass-java in one container.
# Render handles TLS termination (HTTPS guaranteed).
#
# Security conditions met:
#   1. HTTPS: Render terminates TLS at their edge — all traffic is HTTPS.
#   2. Memcached private: listens only on 127.0.0.1 (unreachable from internet).
#   3. Logs: stay inside the container; Render log drain is opt-in.

set -e

# Start memcached in background (64MB, localhost only, binary protocol)
memcached -m 64 -I 1m -c 256 -t 2 -u memcached -l 127.0.0.1 -d

# Wait for Memcached to be ready (up to 10 seconds)
echo "Waiting for Memcached to be ready..."
RETRIES=20
until printf "version\r\n" | nc -w 1 127.0.0.1 11211 > /dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  if [ "$RETRIES" -le 0 ]; then
    echo "ERROR: Memcached failed to start within 10 seconds" >&2
    exit 1
  fi
  sleep 0.5
done
echo "Memcached is ready."

echo "Starting yopass-java on port ${PORT:-10000}..."

# Start yopass-java. Drop privileges to 'yopass' user.
# PORT is set automatically by Render (default 10000).
# YP_MEMCACHED defaults to localhost:11211 (set in application code).
exec su-exec yopass java \
  -XX:+UseContainerSupport \
  -XX:MaxRAMPercentage=75.0 \
  -Djava.security.egd=file:/dev/urandom \
  -jar /app/yopass-java.jar
