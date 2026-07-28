package se.jhaals;

import net.rubyeye.xmemcached.MemcachedClient;
import net.rubyeye.xmemcached.MemcachedClientBuilder;
import net.rubyeye.xmemcached.XMemcachedClientBuilder;
import net.rubyeye.xmemcached.command.BinaryCommandFactory;
import net.rubyeye.xmemcached.utils.AddrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Singleton Memcached client wrapper.
 * Reuses a single connection across requests instead of creating one per request.
 */
//@SuppressWarnings({ "PMD.OnlyOneReturn", "PMD.AvoidCatchingGenericException", "PMD.CommentSize" })
public final class Memcached {
    /** Logger for the Memcached class. */
    private static final Logger LOG = LoggerFactory.getLogger(Memcached.class);
    /** Singleton instance of the Memcached class. */
    private static volatile Memcached instance; // NOPMD AvoidUsingVolatile
    /** Memcached client used for interacting with the Memcached server. */
    private final MemcachedClient client;

    private Memcached() throws IOException {
        final String address = System.getenv("YP_MEMCACHED") != null
                ? System.getenv("YP_MEMCACHED")
                : "localhost:11211";
        LOG.info("Connecting to Memcached at {}", address);

        final MemcachedClientBuilder builder = new XMemcachedClientBuilder(AddrUtil.getAddresses(address));
        builder.setFailureMode(false);
        builder.setCommandFactory(new BinaryCommandFactory());
        builder.setConnectionPoolSize(5);

        client = builder.build();
        client.setEnableHealSession(true);
    }

    /**
     * Returns the singleton Memcached instance.
     * Uses the local-variable idiom (Effective Java, Item 83) to ensure
     * the volatile field is read at most once in the common path.
     *
     * @throws UncheckedIOException if the Memcached connection cannot be established
     */
    public static Memcached getInstance() { // NOPMD SingletonClassReturningNewInstance
        Memcached result = instance;
        if (result == null) {
            synchronized (Memcached.class) { // NOPMD AvoidSynchronizedStatement
                result = instance;
                if (result == null) {
                    try {
                        result = new Memcached();
                    } catch (final IOException e) {
                        throw new UncheckedIOException("Failed to connect to Memcached", e);
                    }
                    instance = result;
                }
            }
        }
        return result;
    }

    /**
     * Saves a key-value pair to Memcached with a specified lifetime.
     *
     * @param key      the Memcached key
     * @param lifetime the lifetime of the key in seconds
     * @param value    the value to store
     * @return true if the save operation was successful, false otherwise
     */
    public boolean save(final String key, final int lifetime, final String value) {
        try {
            client.add(key, lifetime, value);
            return true;
        } catch (final Exception e) {
            LOG.error("Failed to save key '{}' to Memcached", key, e);
            return false;
        }
    }

    /**
     * Retrieves a value from Memcached for the given key.
     *
     * @param key the Memcached key
     * @return the value associated with the key, or null if not found or on error
     */
    public String get(final String key) {
        try {
            return client.get(key);
        } catch (final Exception e) {
            LOG.error("Failed to get key '{}' from Memcached", key, e);
            return null;
        }
    }

    /**
     * Atomically retrieves and deletes a key from Memcached.
     * Uses delete-as-claim: only the request that successfully deletes
     * the key is allowed to return the value, preventing concurrent
     * readers from both obtaining the secret (TOCTOU race fix).
     *
     * @param key the Memcached key
     * @return the value if this caller successfully claimed it, or null
     */
    public String getAndDelete(final String key) {
        try {
            final String value = client.get(key);
            if (value == null) {
                return null;
            }
            // Memcached delete is atomic: only one concurrent caller
            // will receive 'DELETED'; others will get 'NOT_FOUND'.
            if (!client.delete(key)) {
                // Another request already consumed this secret
                if(LOG.isWarnEnabled()) {
                    LOG.warn("Concurrent access detected for key prefix '{}'", key.substring(0, 6));
                }
                return null;
            }
            return value;
        } catch (final Exception e) {
            LOG.error("Failed to getAndDelete key from Memcached", e);
            return null;
        }
    }

    /**
     * Increments a numeric value in Memcached for the given key.
     * If the key does not exist, it will be created with an initial value of 1.
     *
     * @param key the Memcached key
     * @return true if the increment operation was successful, false otherwise
     */
    public boolean increment(final String key) {
        try {
            client.incr(key, 43_200, 1);
            return true;
        } catch (final Exception e) {
            LOG.error("Failed to increment key '{}' in Memcached", key, e);
            return false;
        }
    }

    /**
     * Checks whether the Memcached server is reachable.
     * Unlike {@link #get(String)}, this method does NOT swallow exceptions,
     * so callers can distinguish "key not found" from "server unreachable".
     *
     * @return true if the server responded, false if it is unreachable
     */
    public boolean isAvailable() {
        try {
            client.get("__healthcheck__");
            return true;
        } catch (final Exception e) {
            LOG.warn("Memcached availability check failed", e);
            return false;
        }
    }

    /**
     * Shuts down the Memcached client connection.
     */
    public void shutdown() {
        try {
            if (client != null && !client.isShutdown()) {
                client.shutdown();
                LOG.info("Memcached client shut down");
            }
        } catch (final IOException e) {
            LOG.error("Error shutting down Memcached client", e);
        }
    }

}