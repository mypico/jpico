package org.mypico.jpico.test.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.mypico.jpico.crypto.BrowserAuthToken;
import org.mypico.jpico.crypto.Cookie;

public class BrowserAuthTokenTest {

    private static final String COOKIE_SETTING_PAGE_1 = "http://example.org/";
    private static final String COOKIE_STRING_1 = "cookie1value1";
    private static final String COOKIE_SETTING_PAGE_2 = "http://example.org/page2.html";
    private static final String COOKIE_STRING_2 = "cookie2value2";
    private static Collection<Cookie> NO_COOKIE_STRINGS =
            new ArrayList<Cookie>();
    private static Collection<Cookie> SOME_COOKIE_STRINGS =
            new ArrayList<Cookie>();
    private static final URL LOGIN_URL;
    private static final URL REDIRECT_URL;

    static {
        try {
            LOGIN_URL = new URL("http://www.example.com/login/");
            REDIRECT_URL = new URL("http://www.example.com/redirect/");
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        SOME_COOKIE_STRINGS.add(new Cookie(COOKIE_SETTING_PAGE_1, COOKIE_STRING_1, null));
        SOME_COOKIE_STRINGS.add(new Cookie(COOKIE_SETTING_PAGE_2, COOKIE_STRING_2, null));
    }

    @Test
    public void testSerializeCycle() throws Exception {
        BrowserAuthToken t =
                new BrowserAuthToken(SOME_COOKIE_STRINGS, LOGIN_URL, REDIRECT_URL, "");
        assertTrue(t.equals(t));
        byte[] inTransmission = t.toByteArray();
        BrowserAuthToken actual = BrowserAuthToken.fromByteArray(inTransmission);
        assertEquals(t, actual);
    }

    @Test
    public void testSerializeSame() throws Exception {
        BrowserAuthToken t =
                new BrowserAuthToken(SOME_COOKIE_STRINGS, LOGIN_URL, REDIRECT_URL, "");
        assertTrue(Arrays.equals(t.toByteArray(), t.toByteArray()));
    }

    @Test
    public void testSerializeNoCookiesCycle() throws Exception {
        BrowserAuthToken t =
                new BrowserAuthToken(NO_COOKIE_STRINGS, LOGIN_URL, REDIRECT_URL, "");
        assertEquals(t, BrowserAuthToken.fromByteArray(t.toByteArray()));
    }

    @Test
    public void testSerializeNoCookiesSame() throws Exception {
        BrowserAuthToken t =
                new BrowserAuthToken(NO_COOKIE_STRINGS, LOGIN_URL, REDIRECT_URL, "");
        assertTrue(Arrays.equals(t.toByteArray(), t.toByteArray()));
    }

    @Test
    public void testGetFull() throws Exception {
        BrowserAuthToken t =
                new BrowserAuthToken(SOME_COOKIE_STRINGS, LOGIN_URL, REDIRECT_URL, "");
        String is = t.getFull();
        String start = "{\"cookieStrings\":[{\"url\":\"" +
                COOKIE_SETTING_PAGE_1 +
                "\",\"value\":\"" +
                COOKIE_STRING_1 +
                "\",\"date\":\"";
        String middle = "\"},{\"url\":\"" +
                COOKIE_SETTING_PAGE_2 +
                "\",\"value\":\"" +
                COOKIE_STRING_2
                + "\",\"date\":\"";
        String end = "\"}],\"loginUrl\":\"" +
                LOGIN_URL
                + "\",\"redirectUrl\":\""
                + REDIRECT_URL + "\",\"responseBody\":\"\"}";
        assertTrue(is.startsWith(start));
        assertTrue(is.contains(middle));
        assertTrue(is.endsWith(end));
    }

    @Test
    public void testGetFullNoCookies() throws Exception {
        BrowserAuthToken t =
                new BrowserAuthToken(NO_COOKIE_STRINGS, LOGIN_URL, REDIRECT_URL, "");
        String is = t.getFull();
        String shouldBe =
                "{\"cookieStrings\":[],\"loginUrl\":\"" + LOGIN_URL + "\",\"redirectUrl\":\""
                        + REDIRECT_URL + "\",\"responseBody\":\"\"}";
        assertEquals(shouldBe, is);
    }

    @Test
    public void testGetFallback() throws Exception {
        BrowserAuthToken t =
                new BrowserAuthToken(NO_COOKIE_STRINGS, LOGIN_URL, REDIRECT_URL, "");
        assertEquals(REDIRECT_URL.toString(), t.getFallback());
    }

}
