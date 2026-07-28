package se.jhaals;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.rubyeye.xmemcached.MemcachedClient;
import net.rubyeye.xmemcached.MemcachedClientBuilder;
import net.rubyeye.xmemcached.XMemcachedClientBuilder;
import net.rubyeye.xmemcached.command.BinaryCommandFactory;
import net.rubyeye.xmemcached.utils.AddrUtil;

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
     * Uses {@code add} (not {@code set}) so the operation fails if the key
     * already exists, preventing silent overwrites on key collision.
     *
     * @param key      the Memcached key
     * @param lifetime the lifetime of the key in seconds
     * @param value    the value to store
     * @return true if the key was stored successfully, false if it already existed or on error
     */
    public boolean save(final String key, final int lifetime, final String value) {
        try {
            final boolean stored = client.add(key, lifetime, value);
            if (!stored) {
                LOG.warn("Key collision detected for key prefix '{}'", key.substring(0, 6));
            }
            return stored;
        } catch (final Exception e) {
            LOG.error("Failed to save key prefix '{}' to Memcached", key.substring(0, 6), e);
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
            LOG.error("Failed to get key prefix '{}' from Memcached", key.substring(0, 6), e);
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
     * Checks whether the Memcached server is reachable by sending a
     * protocol-level {@code VERSION} command.
     * <p>
     * Unlike {@link #get(String)} (which returns {@code null} on both
     * "key not found" and "server error"), this method returns a clear
     * boolean so callers can distinguish a healthy server from an
     * unreachable one.
     *
     * @return true if at least one Memcached node responded, false otherwise
     */
    public boolean isAvailable() {
        try {
            final Map<InetSocketAddress, String> versions = client.getVersions();
            return versions != null && !versions.isEmpty();
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