package se.jhaals;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Simple in-memory rate limiter based on IP address.
 * Limits each IP to a maximum number of requests per time window.
 * Not distributed — suitable for single-instance deployments.
 * <p>
 * Automatically evicts stale entries every {@value #CLEANUP_INTERVAL_MINUTES}
 * minutes via a background daemon thread to prevent unbounded memory growth.
 */
//@SuppressWarnings({ "PMD.DoNotUseThreads", "PMD.LawOfDemeter" })
//, "PMD.AvoidUsingVolatile", "PMD.AvoidSynchronizedAtMethodLevel"
public class RateLimiter {
    /** Maximum number of requests allowed per IP within the time window. */
    private static final int MAX_REQUESTS_PER_WINDOW = 30; // NOPMD LongVariable
    /** Time window in milliseconds (1 minute). */
    private static final long WINDOW_MS = 60_000; // 1 minute
    /** Interval in minutes between cleanup runs. */
    private static final int CLEANUP_INTERVAL_MINUTES = 5; // NOPMD LongVariable
    /** Staleness multiplier: entries older than WINDOW_MS * STALE_FACTOR are evicted. */
    private static final int STALE_FACTOR = 5;
    /** Map to hold request counts and window start times for each IP. */
    private final Map<String, WindowCounter> counters = new ConcurrentHashMap<>();
    /** Scheduled executor for periodic cleanup of stale entries. */
    private final ScheduledExecutorService scheduler;

    /**
     * Inner class to hold the request count and window start time for an IP.
     */
    private static final class WindowCounter {
        /** Atomic counter for the number of requests made in the current window. */
        /*default*/ final AtomicInteger count = new AtomicInteger(0);
        /** Timestamp marking the start of the current time window. */
        /*default*/ volatile long windowStart = System.currentTimeMillis(); // NOPMD AvoidUsingVolatile
    }

    /**
     * Creates a RateLimiter and starts the background cleanup scheduler.
     */
    public RateLimiter() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread thread = new Thread(r, "rate-limiter-cleanup");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleAtFixedRate(
                this::cleanup,
                CLEANUP_INTERVAL_MINUTES,
                CLEANUP_INTERVAL_MINUTES,
                TimeUnit.MINUTES
        );
    }

    /**
     * Returns true if the request should be allowed, false if rate-limited.
     */
    public boolean allowRequest(final String clientIp) {
        final WindowCounter counter = counters.computeIfAbsent(clientIp, k -> new WindowCounter());

        final long now = System.currentTimeMillis();
        if (now - counter.windowStart > WINDOW_MS) {
            // Reset window
            synchronized (counter) { // NOPMD AvoidSynchronizedStatement
                if (now - counter.windowStart > WINDOW_MS) {
                    counter.count.set(0);
                    counter.windowStart = now;
                }
            }
        }

        return counter.count.incrementAndGet() <= MAX_REQUESTS_PER_WINDOW;
    }

    /**
     * Removes stale entries (IPs that haven't made requests in a while)
     * to prevent unbounded memory growth.
     */
    /*default*/ void cleanup() {
        final long now = System.currentTimeMillis();
        counters.entrySet().removeIf(entry -> now - entry.getValue().windowStart > WINDOW_MS * STALE_FACTOR);
    }

    /** Shuts down the background cleanup scheduler. */
    /*default*/ void shutdown() {
        scheduler.shutdownNow();
    }

}