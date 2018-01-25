package org.mypico.jpico.test.crypto;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.mypico.jpico.crypto.Cookie;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class CookieTest {

    private static final Gson GSON = new GsonBuilder().create();

    @Test
    public void testCookie() {
        Cookie c = new Cookie("URL", "Value", null);
        String json = GSON.toJson(c);
        Cookie c2 = GSON.fromJson(json, Cookie.class);
        assertEquals(c, c2);
    }
}
