package org.mypico.jpico.test.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;
import org.mypico.jpico.crypto.SimpleAuthToken;

public class SimpleAuthTokenTest {

    private static final String TOKEN_STRING = "tokenString";

    @Test
    public void testSerializeCycle() throws Exception {
        SimpleAuthToken t = new SimpleAuthToken(TOKEN_STRING);
        assertEquals(t, SimpleAuthToken.fromByteArray(t.toByteArray()));
    }

    @Test
    public void testSerializeSame() throws Exception {
        SimpleAuthToken t = new SimpleAuthToken(TOKEN_STRING);
        assertTrue(Arrays.equals(t.toByteArray(), t.toByteArray()));
    }

    @Test
    public void testGetFull() throws Exception {
        SimpleAuthToken t = new SimpleAuthToken(TOKEN_STRING);
        assertEquals(TOKEN_STRING, t.getFull());
    }

    @Test
    public void testGetFallback() throws Exception {
        SimpleAuthToken t = new SimpleAuthToken(TOKEN_STRING);
        assertEquals(TOKEN_STRING, t.getFallback());
    }
}
