package se.jhaals;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for Yopass utility methods.
 */
class YopassTest {

    @ParameterizedTest
    @CsvSource({
        "1h,   3600",
        "1d,  86400",
        "1w, 604800"
    })
    @DisplayName("getLifeTime returns correct seconds for valid durations")
    void testGetLifeTime(final String input, final int expectedSeconds) {
        assertEquals(expectedSeconds, Yopass.getLifeTime(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"JEBUS", "2h", "30d", "", "abc"})
    @DisplayName("getLifeTime defaults to 3600 for unrecognized values")
    void testGetLifeTimeUnrecognized(final String input) {
        assertEquals(3_600, Yopass.getLifeTime(input));
    }

    @Test
    @DisplayName("getLifeTime returns 3600 for null input")
    void testGetLifeTimeNull() {
        assertEquals(3_600, Yopass.getLifeTime(null));
    }

    @Test
    @DisplayName("generateSecureRandom produces correct length")
    void testGenerateSecureRandomLength() {
        assertEquals(22, Yopass.generateSecureRandom(22).length());
        assertEquals(1, Yopass.generateSecureRandom(1).length());
        assertEquals(100, Yopass.generateSecureRandom(100).length());
    }

    @Test
    @DisplayName("generateSecureRandom produces only alphanumeric characters")
    void testGenerateSecureRandomAlphanumeric() {
        final String random = Yopass.generateSecureRandom(1000);
        assertTrue(random.matches("[A-Za-z0-9]+"),
                "Should only contain alphanumeric characters");
    }

    @Test
    @DisplayName("generateSecureRandom produces different values (non-deterministic)")
    void testGenerateSecureRandomUniqueness() {
        final String r1 = Yopass.generateSecureRandom(22);
        final String r2 = Yopass.generateSecureRandom(22);
        assertNotEquals(r1, r2, "Two random strings should differ (probabilistically)");
    }

    @Test
    @DisplayName("generateSecureRandom with length 0 returns empty string")
    void testGenerateSecureRandomZeroLength() {
        assertEquals("", Yopass.generateSecureRandom(0));
    }

    @Test
    @DisplayName("KEY_LENGTH constant is 22")
    void testKeyLengthConstant() {
        assertEquals(22, Yopass.KEY_LENGTH);
    }

    @Test
    @DisplayName("SECRET_MAX_LENGTH constant is 100000")
    void testSecretMaxLengthConstant() {
        assertEquals(100_000, Yopass.SECRET_MAX_LENGTH);
    }
}