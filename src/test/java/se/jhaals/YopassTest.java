package se.jhaals;

import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;

public class YopassTest extends TestCase {

    public void testGetLifeTime() {
        assertEquals(  3_600, Yopass.getLifeTime("JEBUS"));
        assertEquals(  3_600, Yopass.getLifeTime("1h"));
        assertEquals( 86_400, Yopass.getLifeTime("1d"));
        assertEquals(604_800, Yopass.getLifeTime("1w"));
    }

    public void testGetLifeTimeNull() {
        assertEquals(3600, Yopass.getLifeTime(null));
    }

    public void testGenerateSecureRandom() {
        final String random1 = Yopass.generateSecureRandom(22);
        final String random2 = Yopass.generateSecureRandom(22);
        assertEquals(22, random1.length());
        assertEquals(22, random2.length());
        // Should be different (probabilistically)
        assertNotEquals(random1, random2);
        // Should only contain alphanumeric characters
        assertTrue(random1.matches("[A-Za-z0-9]+"));
    }

}