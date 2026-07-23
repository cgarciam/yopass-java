package se.jhaals;

import static spark.Spark.*;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Map;

/**
 * Yopass - Share secrets securely with zero-knowledge architecture. Secrets are
 * encrypted client-side (Web Crypto API AES-GCM) before being sent to the
 * server. The server never sees plaintext secrets or decryption keys.
 */
//@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.GuardLogStatement", "PMD.UseUtilityClass" })
public class Yopass {
    /**
     * Content type for JSON responses.
     */
    private static final String APPLICATION_JSON = "application/json";
    /**
     * Key used in JSON responses for messages.
     */
    private static final String MESSAGE = "message";
    /**
     * Logger for Yopass class.
     */
    private static final Logger LOG = LoggerFactory.getLogger(Yopass.class);
    /**
     * Length of the generated key for storing secrets.
     */
    public static final int KEY_LENGTH = 22;
    /**
     * Maximum allowed length for the encrypted secret (ciphertext).
     */
    public static final int SECRET_MAX_LENGTH = 100_000;
    /**
     * Maximum allowed size for the request body.
     */
    private static final int MAX_BODY_SIZE = 150_000;
    /**
     * SecureRandom instance for generating cryptographically secure random values.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    /**
     * Alphanumeric characters used for generating random keys.
     */
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * Map of lifetime strings to their corresponding TTL in seconds.
     */
    // Correct durations: 1h = 3600s, 1d = 86400s, 1w = 604800s
    private static final Map<String, Integer> DURATIONS = Map.of(
            "1h",   3_600,
            "1d",  86_400,
            "1w", 604_800
    );

    /**
     * Returns the TTL in seconds for a given lifetime string.
     * Defaults to 3600 (1 hour) if the value is unrecognized.
     */
    public static int getLifeTime(final String lifetime) {
        final int lifetimeValue;
        if (lifetime == null) {
            lifetimeValue = 3_600;
        } else {
            lifetimeValue = DURATIONS.getOrDefault(lifetime, 3_600);
        }
        return lifetimeValue;
    }

    /**
     * Generates a cryptographically secure random alphanumeric string.
     */
    public static String generateSecureRandom(final int length) {
        final StringBuilder sRandom = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sRandom.append(ALPHANUMERIC.charAt(SECURE_RANDOM.nextInt(ALPHANUMERIC.length())));
        }
        return sRandom.toString();
    }

    /**
     * Main method to start the Yopass server.
     */
    public static void main(final String... args) {
        final String portEnv = setupPort();

        staticFileLocation("/public");

        // Initialize Memcached connection at startup
        try {
            Memcached.getInstance();
        } catch (final Exception e) {
            LOG.error("Failed to connect to Memcached at startup. Exiting.", e);
            System.exit(1);
            return;
        }

        // Graceful shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("Shutting down Yopass...");
            stop();
            try {
                Memcached.getInstance().shutdown();
            } catch (final Exception ignored) {
                // Ignore exceptions during shutdown
            }
        }));

        // Security headers for all responses
        after((req, res) -> {
            res.header("X-Content-Type-Options", "nosniff");
            res.header("X-Frame-Options", "DENY");
            res.header("X-XSS-Protection", "1; mode=block");
            res.header("Referrer-Policy", "no-referrer");
            res.header("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'");
            res.header("Cache-Control", "no-store, no-cache, must-revalidate, private");
            res.header("Pragma", "no-cache");
            res.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        });

        // Global rate limiter (30 requests per minute per IP)
        final RateLimiter rateLimiter = new RateLimiter();
        before("/v1/*", (req, res) -> {
            if (!rateLimiter.allowRequest(req.ip())) {
                halt(429, new JSONObject().put(MESSAGE, "Too many requests").toString());
            }
        });

        // Set response type for all API routes
        before("/v1/*", (req, res) -> res.type(APPLICATION_JSON));

        // Health check endpoint
        get("/healthz", (req, res) -> {
            res.type(APPLICATION_JSON);
            try {
                // Attempt a simple operation to verify connectivity
                Memcached.getInstance().get("__healthcheck__");
                return new JSONObject().put("status", "ok");
            } catch (final Exception e) {
                res.status(503);
                return new JSONObject().put("status", "unhealthy").put("error", "memcached unavailable");
            }
        });

        // Global exception handler
        exception(Exception.class, (e, req, res) -> {
            LOG.error("Unhandled exception on {} {}", req.requestMethod(), req.pathInfo(), e);
            res.status(500);
            res.type(APPLICATION_JSON);
            res.body(new JSONObject().put(MESSAGE, "Internal server error").toString());
        });

        // Store a secret (receives already-encrypted ciphertext from the client)
        post("/v1/secret", (request, response) -> {
            // Body size check (contentLength can be -1 if not sent, so also check actual body)
            final int contentLength = request.contentLength();
            if (contentLength > MAX_BODY_SIZE || (contentLength == -1 && request.body().length() > MAX_BODY_SIZE)) {
                halt(413, new JSONObject().put(MESSAGE, "Payload too large").toString());
                return null;
            }

            final JSONObject jsonObject;
            try {
                jsonObject = new JSONObject(request.body());
            } catch (JSONException e) {
                halt(400, new JSONObject().put(MESSAGE, "Invalid JSON").toString());
                return null;
            }

            // Get and validate the encrypted secret (ciphertext from client)
            final String secret = jsonObject.optString("secret", null);
            if (secret == null || secret.isEmpty()) {
                halt(400, new JSONObject().put(MESSAGE, "Secret is required").toString());
                return null;
            }
            if (secret.length() > SECRET_MAX_LENGTH) {
                halt(400, new JSONObject().put(MESSAGE, "Secret exceeds maximum length of " + SECRET_MAX_LENGTH).toString());
                return null;
            }

            // Get lifetime
            final int lifetime = getLifeTime(jsonObject.optString("lifetime", "1h"));

            // Generate storage key (the decryption key is only known to the client)
            final String key = generateSecureRandom(KEY_LENGTH);

            // Store the already-encrypted ciphertext in Memcached
            final Memcached memcached = Memcached.getInstance();
            if (!memcached.save(key, lifetime, secret)) {
                response.status(500);
                return new JSONObject().put(MESSAGE, "Failed to store secret");
            }

            LOG.info("Secret stored, key prefix={}, ttl={}s", key.substring(0, 6), lifetime);

            return new JSONObject()
                    .put("key", key)
                    .put(MESSAGE, "secret stored");
        });

        // Retrieve an encrypted secret (one-time read, then deleted)
        get("/v1/secret/:key", (request, response) -> {
            final String key = request.params(":key");

            // Validate key format
            if (key == null || key.length() != KEY_LENGTH) {
                halt(400, new JSONObject().put(MESSAGE, "Invalid key format").toString());
                return null;
            }

            final Memcached memcached = Memcached.getInstance();
            final String ciphertext = memcached.get(key);
            if (ciphertext == null) {
                halt(404, new JSONObject().put(MESSAGE, "Secret not found or already consumed").toString());
                return null;
            }

            // Delete secret after retrieval (one-time secret)
            memcached.delete(key);

            LOG.info("Secret retrieved and deleted, key prefix='{}'", key.substring(0, 6));

            return new JSONObject()
                    .put(MESSAGE, "OK")
                    .put("secret", ciphertext);
        });

        LOG.info("Yopass started on port {}", portEnv == null ? "4567" : portEnv);
    }

    private static String setupPort() {
        // Configure port: PORT (Render/cloud) takes precedence, then YP_PORT, then
        // default 4567
        final String portEnv = System.getenv("PORT") != null ? System.getenv("PORT") : System.getenv("YP_PORT");
        if (portEnv != null) {
            port(Integer.parseInt(portEnv));
        }
        return portEnv;
    }

}