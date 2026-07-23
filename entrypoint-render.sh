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

# Wait briefly for Memcached to be ready
sleep 1

echo "Starting yopass-java on port ${PORT:-10000}..."

# Start yopass-java. Drop privileges to 'yopass' user.
# PORT is set automatically by Render (default 10000).
# YP_MEMCACHED defaults to localhost:11211 (set in application code).
exec su-exec yopass java \
  -XX:+UseContainerSupport \
  -XX:MaxRAMPercentage=75.0 \
  -Djava.security.egd=file:/dev/urandom \
  -jar /app/yopass-java.jar
