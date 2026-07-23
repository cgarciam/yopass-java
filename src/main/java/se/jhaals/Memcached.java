package se.jhaals;

import net.rubyeye.xmemcached.MemcachedClient;
import net.rubyeye.xmemcached.MemcachedClientBuilder;
import net.rubyeye.xmemcached.XMemcachedClientBuilder;
import net.rubyeye.xmemcached.command.BinaryCommandFactory;
import net.rubyeye.xmemcached.utils.AddrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Singleton Memcached client wrapper.
 * Reuses a single connection across requests instead of creating one per request.
 */
public class Memcached {

    private static final Logger LOG = LoggerFactory.getLogger(Memcached.class);
    private static volatile Memcached instance;
    private final MemcachedClient client;

    private Memcached() throws IOException {
        String address = System.getenv("YP_MEMCACHED") != null
                ? System.getenv("YP_MEMCACHED")
                : "localhost:11211";
        LOG.info("Connecting to Memcached at {}", address);

        MemcachedClientBuilder builder = new XMemcachedClientBuilder(AddrUtil.getAddresses(address));
        builder.setFailureMode(false);
        builder.setCommandFactory(new BinaryCommandFactory());
        builder.setConnectionPoolSize(5);

        client = builder.build();
        client.setEnableHealSession(true);
    }

    /**
     * Returns the singleton Memcached instance.
     */
    public static Memcached getInstance() throws IOException {
        if (instance == null) {
            synchronized (Memcached.class) {
                if (instance == null) {
                    instance = new Memcached();
                }
            }
        }
        return instance;
    }

    public boolean save(String key, int lifetime, String value) {
        try {
            client.add(key, lifetime, value);
            return true;
        } catch (Exception e) {
            LOG.error("Failed to save key '{}' to Memcached", key, e);
            return false;
        }
    }

    public String get(String key) {
        try {
            return client.get(key);
        } catch (Exception e) {
            LOG.error("Failed to get key '{}' from Memcached", key, e);
            return null;
        }
    }

    public boolean delete(String key) {
        try {
            return client.delete(key);
        } catch (Exception e) {
            LOG.error("Failed to delete key '{}' from Memcached", key, e);
            return false;
        }
    }

    public boolean increment(String key) {
        try {
            client.incr(key, 43200, 1);
            return true;
        } catch (Exception e) {
            LOG.error("Failed to increment key '{}' in Memcached", key, e);
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
        } catch (IOException e) {
            LOG.error("Error shutting down Memcached client", e);
        }
    }
}
