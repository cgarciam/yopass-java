package se.jhaals;

import static spark.Spark.*;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Request;

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
//    @SuppressWarnings("PMD.CognitiveComplexity") // TODO: refactor into smaller methods
    private static void startServer() {
        final String portEnv;
        try {
            portEnv = setupPort();
        } catch (final IllegalArgumentException e) {
            throw new IllegalStateException("Invalid port configuration", e);
        }

        staticFileLocation("/public");

        // Initialize Memcached connection at startup and capture the reference.
        // All route handlers close over this variable — no further getInstance()
        // calls (and their volatile reads) are needed on the hot path.
        final Memcached memcached;
        try {
            memcached = Memcached.getInstance();
        } catch (final UncheckedIOException e) {
            throw new IllegalStateException("Failed to connect to Memcached", e);
        }

        // Global rate limiter (30 requests per minute per IP)
        final RateLimiter rateLimiter = new RateLimiter();

        // Graceful shutdown hook — uses the already-captured reference to avoid
        // accidentally creating a new connection during shutdown.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> { // NOPMD DoNotUseThreads
            LOG.info("Shutting down Yopass...");
            stop();
            rateLimiter.shutdown();
            memcached.shutdown();
        }));

        // Security headers for all responses
        after((req, res) -> {
            res.header("X-Content-Type-Options", "nosniff");
            res.header("X-Frame-Options", "DENY");
            res.header("Referrer-Policy", "no-referrer");
            res.header("Content-Security-Policy",
                    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
            res.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
            res.header("Cache-Control", "no-store, no-cache, must-revalidate, private");
            res.header("Pragma", "no-cache");
            res.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            // CORS: restrict to same-origin only (no cross-origin API access)
            res.header("Access-Control-Allow-Origin", "");
            res.header("Cross-Origin-Resource-Policy", "same-origin");
        });

        before("/v1/*", (req, res) -> {
            if (!rateLimiter.allowRequest(getClientIp(req))) {
                halt(429, new JSONObject().put(MESSAGE, "Too many requests").toString());
            }
        });

        // Set response type for all API routes
        before("/v1/*", (req, res) -> res.type(APPLICATION_JSON));

        // Health check endpoint
        get("/healthz", (req, res) -> {
            res.type(APPLICATION_JSON);
            if (memcached.isAvailable()) {
                return new JSONObject().put("status", "ok");
            }
            res.status(503);
            return new JSONObject().put("status", "unhealthy").put("error", "memcached unavailable");
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
            // Validate Content-Type
            final String contentType = request.contentType();
            if (contentType == null || !contentType.toLowerCase(LOCALE).startsWith("application/json")) {
                LOG.warn("Rejected POST with invalid Content-Type '{}' from {}",
                        contentType, getClientIp(request));
                halt(415, new JSONObject().put(MESSAGE, "Content-Type must be application/json").toString());
                return null;
            }

            // Body size check: reject early if Content-Length exceeds limit (#3-5)
            final int contentLength = request.contentLength();
            if (contentLength > MAX_BODY_SIZE) {
                LOG.warn("Rejected oversized payload ({} bytes) from {}", contentLength, getClientIp(request));
                halt(413, new JSONObject().put(MESSAGE, "Payload too large").toString());
                return null;
            }
            // If Content-Length is missing, we must read the body to check size
            if (contentLength == -1 && request.body().length() > MAX_BODY_SIZE) {
                LOG.warn("Rejected oversized payload (no Content-Length) from {}", getClientIp(request));
                halt(413, new JSONObject().put(MESSAGE, "Payload too large").toString());
                return null;
            }

            final JSONObject jsonObject;
            try {
                jsonObject = new JSONObject(request.body());
            } catch (JSONException e) {
                LOG.warn("Rejected malformed JSON from {}", getClientIp(request));
                halt(400, new JSONObject().put(MESSAGE, "Invalid JSON").toString());
                return null;
            }

            // Get and validate the encrypted secret (ciphertext from client)
            final String secret = jsonObject.optString("secret", null);
            if (secret == null || secret.isEmpty()) {
                LOG.warn("Rejected POST with missing secret from {}", getClientIp(request));
                halt(400, new JSONObject().put(MESSAGE, "Secret is required").toString());
                return null;
            }
            if (secret.length() > SECRET_MAX_LENGTH) {
                LOG.warn("Rejected oversized secret ({} chars) from {}", secret.length(), getClientIp(request));
                halt(400, new JSONObject().put(MESSAGE, "Secret exceeds maximum length of " + SECRET_MAX_LENGTH).toString());
                return null;
            }

            // Get lifetime
            final int lifetime = getLifeTime(jsonObject.optString("lifetime", "1h"));

            // Generate storage key (the decryption key is only known to the client)
            final String key = generateSecureRandom(KEY_LENGTH);

            // Store the already-encrypted ciphertext in Memcached
            if (!memcached.save(key, lifetime, secret)) {
                response.status(500);
                return new JSONObject().put(MESSAGE, "Failed to store secret");
            }

            LOG.info("Secret stored, key prefix={}, ttl={}s", key.substring(0, 6), lifetime);

            return new JSONObject()
                    .put("key", key)
                    .put(MESSAGE, "secret stored");
        });

        // Retrieve an encrypted secret (one-time read, then deleted atomically)
        get("/v1/secret/:key", (request, response) -> {
            final String key = request.params(":key");

            // Validate key format (must be exactly KEY_LENGTH alphanumeric characters)
            if (key == null || key.length() != KEY_LENGTH || !key.matches("^[A-Za-z0-9]+$")) {
                LOG.warn("Rejected invalid key format (length={}) from {}",
                        key == null ? 0 : key.length(), getClientIp(request));
                halt(400, new JSONObject().put(MESSAGE, "Invalid key format").toString());
                return null;
            }

            // Atomic get-and-delete: only one concurrent request can claim the secret.
            // Prevents TOCTOU race where two requests could both read the secret
            // before either deletes it.
            final String ciphertext = memcached.getAndDelete(key);
            if (ciphertext == null) {
                halt(404, new JSONObject().put(MESSAGE, "Secret not found or already consumed").toString());
                return null;
            }

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
            final int portNumber;
            try {
                portNumber = Integer.parseInt(portEnv.trim());
            } catch (final NumberFormatException e) {
                LOG.error("Invalid port value '{}': not a valid integer", portEnv);
                throw new IllegalArgumentException("Invalid port: " + portEnv, e);
            }
            if (portNumber < MIN_PORT || portNumber > MAX_PORT) {
                LOG.error("Port {} out of valid range ({}-{})", portNumber, MIN_PORT, MAX_PORT);
                throw new IllegalArgumentException(
                        "Port out of range: " + portNumber + " (must be " + MIN_PORT + "-" + MAX_PORT + ")");
            }
            port(portNumber);
        }
        return portEnv;
    }

    /**
     * Extracts the real client IP address from the request.
     * When running behind a reverse proxy (e.g., Render, Nginx), the actual
     * client IP is in the {@code X-Forwarded-For} header. The leftmost value
     * is the original client; subsequent entries are intermediate proxies.
     * Falls back to {@code req.ip()} when the header is absent.
     *
     * @param req the Spark request
     * @return the resolved client IP address
     */
    private static String getClientIp(final Request req) {
        final String forwarded = req.headers("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) {
            // X-Forwarded-For: client, proxy1, proxy2
            // Take only the leftmost (original client) IP and trim whitespace
            final int comma = forwarded.indexOf(',');
            final String clientIp = (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
            if (!clientIp.isEmpty()) {
                return clientIp;
            }
        }
        return req.ip();
    }

}