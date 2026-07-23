package se.jhaals;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Simple in-memory rate limiter based on IP address.
 * Limits each IP to a maximum number of requests per time window.
 * Not distributed — suitable for single-instance deployments.
 */
public class RateLimiter {
    /**
     * Maximum number of requests allowed per IP within the time window.
     */
    private static final int MAX_REQUESTS_PER_WINDOW = 30;
    /**
     * Time window in milliseconds (1 minute).
     */
    private static final long WINDOW_MS = 60_000; // 1 minute
    /**
     * Map to hold request counts and window start times for each IP.
     */
    private final Map<String, WindowCounter> counters = new ConcurrentHashMap<>();

    /**
     * Inner class to hold the request count and window start time for an IP.
     */
    private static final class WindowCounter {
        /**
         * Atomic counter for the number of requests made in the current window.
         */
        final AtomicInteger count = new AtomicInteger(0);
        /**
         * Timestamp marking the start of the current time window.
         */
        volatile long windowStart = System.currentTimeMillis();
    }

    /**
     * Returns true if the request should be allowed, false if rate-limited.
     */
    public boolean allowRequest(final String clientIp) {
        final WindowCounter counter = counters.computeIfAbsent(clientIp, k -> new WindowCounter());

        final long now = System.currentTimeMillis();
        if (now - counter.windowStart > WINDOW_MS) {
            // Reset window
            synchronized (counter) {
                if (now - counter.windowStart > WINDOW_MS) {
                    counter.count.set(0);
                    counter.windowStart = now;
                }
            }
        }

        return counter.count.incrementAndGet() <= MAX_REQUESTS_PER_WINDOW;
    }

    /**
     * Periodically clean up stale entries to prevent memory leak.
     */
    public void cleanup() {
        final long now = System.currentTimeMillis();
        counters.entrySet().removeIf(entry -> now - entry.getValue().windowStart > WINDOW_MS * 5);
    }
}
