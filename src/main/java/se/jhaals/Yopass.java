package se.jhaals;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Map;

/**
 * Yopass - Share secrets securely with zero-knowledge architecture. Secrets are
 * encrypted client-side (Web Crypto API AES-GCM) before being sent to the
 * server. The server never sees plaintext secrets or decryption keys.
 */
//@SuppressWarnings({ "PMD.CommentSize", "PMD.OnlyOneReturn", "PMD.GuardLogStatement" })
public class Yopass {
    /** Content type for JSON responses with explicit UTF-8 charset. */
    private static final String APPLICATION_JSON = "application/json;charset=utf-8";
    /** Key used in JSON responses for messages. */
    private static final String MESSAGE = "message";
    /** Logger for Yopass class. */
    private static final Logger LOG = LoggerFactory.getLogger(Yopass.class);
    /** Length of the generated key for storing secrets. */
    public static final int KEY_LENGTH = 22;
    /** Maximum allowed length for the encrypted secret (ciphertext). */
    public static final int SECRET_MAX_LENGTH = 100_000;
    /** Maximum allowed size for the request body. */
    private static final int MAX_BODY_SIZE = 150_000;
    /** SecureRandom instance for generating cryptographically secure random values. */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    /** Alphanumeric characters used for generating random keys. */
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    /** Minimum valid TCP port number. */
    private static final int MIN_PORT = 1;
    /** Maximum valid TCP port number. */
    private static final int MAX_PORT = 65_535;
    /** Default port when no environment variable is set. */
    private static final int DEFAULT_PORT = 4567;

    /**
     * Map of lifetime strings to their corresponding TTL in seconds.
     */
    // Correct durations: 1h = 3600s, 1d = 86400s, 1w = 604800s
    private static final Map<String, Integer> DURATIONS = Map.of(
            "1h",   3_600,
            "1d",  86_400,
            "1w", 604_800
    );
    /** Locale used for case-insensitive string comparisons. */
    private static final Locale LOCALE = Locale.ROOT;

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

    /** Main method to start the Yopass server. */
    public static void main(final String... args) {
        try {
            startServer();
        } catch (final IllegalStateException e) {
            LOG.error("Startup failed: {}", e.getMessage(), e);
            System.exit(1);
        }
    }

    /**
     * Initializes and starts the Yopass server.
     * Extracted from {@code main()} so initialization logic can be tested
     * without triggering {@code System.exit()}.
     *
     * @throws IllegalStateException if the server cannot be started (bad port, Memcached unavailable)
     */
//    @SuppressWarnings("PMD.CognitiveComplexity") // TODO refactor to reduce complexity
    private static void startServer() {
        final int port = resolvePort();

        // Initialize Memcached connection at startup and capture the reference.
        final Memcached memcached;
        try {
            memcached = Memcached.getInstance();
        } catch (final UncheckedIOException e) {
            throw new IllegalStateException("Failed to connect to Memcached", e);
        }

        // Global rate limiter (30 requests per minute per IP)
        final RateLimiter rateLimiter = new RateLimiter();

        // Create Javalin app with static files and all routes
        final Javalin app = Javalin.create(config -> {
            config.staticFiles.add("/public");
            config.http.maxRequestSize = MAX_BODY_SIZE; // NOPMD Law of Demeter

            // Security headers for all responses
            config.routes.after(ctx -> {
                ctx.header("X-Content-Type-Options", "nosniff");
                ctx.header("X-Frame-Options", "DENY");
                ctx.header("Referrer-Policy", "no-referrer");
                ctx.header("Content-Security-Policy",
                        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
                ctx.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
                ctx.header("Cache-Control", "no-store, no-cache, must-revalidate, private");
                ctx.header("Pragma", "no-cache");
                ctx.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
                // CORS: restrict to same-origin only (no cross-origin API access)
                ctx.header("Access-Control-Allow-Origin", "");
                ctx.header("Cross-Origin-Resource-Policy", "same-origin");
            });

            // Rate limiting for API routes
            config.routes.before("/v1/*", ctx -> {
                if (!rateLimiter.allowRequest(getClientIp(ctx))) {
                    ctx.status(HttpStatus.TOO_MANY_REQUESTS)
                       .contentType(APPLICATION_JSON)
                       .result(new JSONObject().put(MESSAGE, "Too many requests").toString());
                    ctx.skipRemainingHandlers();
                    return;
                }
                ctx.contentType(APPLICATION_JSON);
            });

            // Health check endpoint
            config.routes.get("/healthz", ctx -> {
                ctx.contentType(APPLICATION_JSON);
                if (memcached.isAvailable()) {
                    ctx.result(new JSONObject().put("status", "ok").toString());
                } else {
                    ctx.status(HttpStatus.SERVICE_UNAVAILABLE)
                       .result(new JSONObject().put("status", "unhealthy").put("error", "memcached unavailable").toString());
                }
            });

            // Store a secret (receives already-encrypted ciphertext from the client)
            config.routes.post("/v1/secret", ctx -> {
                // Validate Content-Type
                final String contentType = ctx.contentType();
                if (contentType == null || !contentType.toLowerCase(LOCALE).startsWith("application/json")) {
                    LOG.warn("Rejected POST with invalid Content-Type '{}' from {}",
                            contentType, getClientIp(ctx));
                    ctx.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                       .result(new JSONObject().put(MESSAGE, "Content-Type must be application/json").toString());
                    return;
                }

                // Body size check
                if (ctx.contentLength() > MAX_BODY_SIZE) {
                    LOG.warn("Rejected oversized payload ({} bytes) from {}", ctx.contentLength(), getClientIp(ctx));
                    ctx.status(HttpStatus.CONTENT_TOO_LARGE)
                       .result(new JSONObject().put(MESSAGE, "Payload too large").toString());
                    return;
                }

                final JSONObject jsonObject;
                try {
                    jsonObject = new JSONObject(ctx.body());
                } catch (JSONException e) {
                    LOG.warn("Rejected malformed JSON from {}", getClientIp(ctx));
                    ctx.status(HttpStatus.BAD_REQUEST)
                       .result(new JSONObject().put(MESSAGE, "Invalid JSON").toString());
                    return;
                }

                // Get and validate the encrypted secret (ciphertext from client)
                final String secret = jsonObject.optString("secret", null);
                if (secret == null || secret.isEmpty()) {
                    LOG.warn("Rejected POST with missing secret from {}", getClientIp(ctx));
                    ctx.status(HttpStatus.BAD_REQUEST)
                       .result(new JSONObject().put(MESSAGE, "Secret is required").toString());
                    return;
                }
                if (secret.length() > SECRET_MAX_LENGTH) {
                    LOG.warn("Rejected oversized secret ({} chars) from {}", secret.length(), getClientIp(ctx));
                    ctx.status(HttpStatus.BAD_REQUEST)
                       .result(new JSONObject().put(MESSAGE, "Secret exceeds maximum length of " + SECRET_MAX_LENGTH).toString());
                    return;
                }

                // Get lifetime
                final int lifetime = getLifeTime(jsonObject.optString("lifetime", "1h"));

                // Generate storage key (the decryption key is only known to the client)
                final String key = generateSecureRandom(KEY_LENGTH);

                // Store the already-encrypted ciphertext in Memcached
                if (!memcached.save(key, lifetime, secret)) {
                    ctx.status(HttpStatus.INTERNAL_SERVER_ERROR)
                       .result(new JSONObject().put(MESSAGE, "Failed to store secret").toString());
                    return;
                }

                LOG.info("Secret stored, key prefix={}, ttl={}s", key.substring(0, 6), lifetime);

                ctx.result(new JSONObject()
                        .put("key", key)
                        .put(MESSAGE, "secret stored").toString());
            });

            // Report decryption failure (client-side decryption failed, e.g. wrong key)
            config.routes.post("/v1/secret/decryption-failure", ctx -> {
                final JSONObject jsonObject;
                try {
                    jsonObject = new JSONObject(ctx.body());
                } catch (JSONException e) {
                    ctx.status(HttpStatus.BAD_REQUEST)
                       .result(new JSONObject().put(MESSAGE, "Invalid JSON").toString());
                    return;
                }

                final String key = jsonObject.optString("key", "");
                // Only log a safe prefix (first 6 chars) — never log the full storage key
                final String keyPrefix = key.length() >= 6 ? key.substring(0, 6) : key;

                LOG.warn("Decryption failure reported for key prefix='{}' from {}",
                        keyPrefix, getClientIp(ctx));

                ctx.result(new JSONObject().put(MESSAGE, "Failure recorded").toString());
            });

            // Retrieve an encrypted secret (one-time read, then deleted atomically)
            config.routes.get("/v1/secret/{key}", ctx -> {
                final String key = ctx.pathParam("key");

                // Validate key format (must be exactly KEY_LENGTH alphanumeric characters)
                if (key.length() != KEY_LENGTH || !key.matches("^[A-Za-z0-9]+$")) {
                    LOG.warn("Rejected invalid key format (length={}) from {}",
                            key.length(), getClientIp(ctx));
                    ctx.status(HttpStatus.BAD_REQUEST)
                       .result(new JSONObject().put(MESSAGE, "Invalid key format").toString());
                    return;
                }

                // Atomic get-and-delete: only one concurrent request can claim the secret.
                final String ciphertext = memcached.getAndDelete(key);
                if (ciphertext == null) {
                    ctx.status(HttpStatus.NOT_FOUND)
                       .result(new JSONObject().put(MESSAGE, "Secret not found or already consumed").toString());
                    return;
                }

                LOG.info("Secret retrieved and deleted, key prefix='{}'", key.substring(0, 6));

                ctx.result(new JSONObject()
                        .put(MESSAGE, "OK")
                        .put("secret", ciphertext).toString());
            });

            // Global exception handler
            config.routes.exception(Exception.class, (e, ctx) -> {
                LOG.error("Unhandled exception on {} {} {}", ctx.method(), ctx.path(), e);
                ctx.status(HttpStatus.INTERNAL_SERVER_ERROR)
                   .contentType(APPLICATION_JSON)
                   .result(new JSONObject().put(MESSAGE, "Internal server error").toString());
            });
        });

        // Graceful shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> { // NOPMD DoNotUseThreads
            LOG.info("Shutting down Yopass...");
            app.stop();
            rateLimiter.shutdown();
            memcached.shutdown();
        }));

        app.start(port);
        LOG.info("Yopass started on port {}", port);
    }

    /**
     * Resolves the server port from environment variables.
     * PORT (Render/cloud) takes precedence, then YP_PORT, then default 4567.
     *
     * @return the resolved port number
     * @throws IllegalStateException if the port value is invalid
     */
    private static int resolvePort() {
        final String portEnv = System.getenv("PORT") != null ? System.getenv("PORT") : System.getenv("YP_PORT");
        if (portEnv == null) {
            return DEFAULT_PORT;
        }
        final int portNumber;
        try {
            portNumber = Integer.parseInt(portEnv.trim());
        } catch (final NumberFormatException e) {
            LOG.error("Invalid port value '{}': not a valid integer", portEnv);
            throw new IllegalStateException("Invalid port: " + portEnv, e);
        }
        if (portNumber < MIN_PORT || portNumber > MAX_PORT) {
            LOG.error("Port {} out of valid range ({}-{})", portNumber, MIN_PORT, MAX_PORT);
            throw new IllegalStateException(
                    "Port out of range: " + portNumber + " (must be " + MIN_PORT + "-" + MAX_PORT + ")");
        }
        return portNumber;
    }

    /**
     * Extracts the real client IP address from the request.
     * When running behind a reverse proxy (e.g., Render, Nginx), the actual
     * client IP is in the {@code X-Forwarded-For} header. The leftmost value
     * is the original client; subsequent entries are intermediate proxies.
     * Falls back to {@code ctx.ip()} when the header is absent.
     *
     * @param ctx the Javalin context
     * @return the resolved client IP address
     */
    private static String getClientIp(final Context ctx) {
        final String forwarded = ctx.header("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) {
            // X-Forwarded-For: client, proxy1, proxy2
            final int comma = forwarded.indexOf(',');
            final String clientIp = (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
            if (!clientIp.isEmpty()) {
                return clientIp;
            }
        }
        return ctx.ip();
    }

}
