/*
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * This file is part of jpico.
 *
 * jpico is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * jpico is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with jpico. If not, see
 * <http://www.gnu.org/licenses/>.
 */


package org.mypico.jpico.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.mypico.jpico.crypto.util.LengthPrependedDataInputStream;
import org.mypico.jpico.crypto.util.LengthPrependedDataOutputStream;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.base.Objects;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

/**
 * An AuthToken implementation encapsulating a URL to redirect the user's web browser to and zero or
 * more cookies to be loaded into the users web browser.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class BrowserAuthToken implements AuthToken {

    @Deprecated
    private static class GsonSerializer implements
        JsonSerializer<BrowserAuthToken>,
        JsonDeserializer<BrowserAuthToken> {

        private static final String COOKIE_STRINGS_KEY = "cookieStrings";
        private static final String LOGIN_URL_KEY = "loginUrl";
        private static final String REDIRECT_URL_KEY = "redirectUrl";
        private static final String RESPONSE_BODY_KEY = "responseBody";

        @Override
        public BrowserAuthToken deserialize(
            JsonElement element,
            Type type,
            JsonDeserializationContext context) throws JsonParseException {
            JsonObject obj = element.getAsJsonObject();

            // Make cookie strings list
            List<Cookie> cookieStrings = new ArrayList<Cookie>();
            JsonArray cookieStringsElement =
                obj.get(COOKIE_STRINGS_KEY).getAsJsonArray();
            for (JsonElement e : cookieStringsElement) {
                cookieStrings.add((Cookie) context.deserialize(e, Cookie.class));
            }

            // Make login url
            JsonElement loginUrlElement = obj.get(LOGIN_URL_KEY);
            URL loginUrl = null;
            try {
                loginUrl = new URL(
                    loginUrlElement.getAsJsonPrimitive().getAsString());
            } catch (MalformedURLException e) {
                throw new JsonParseException(e);
            }


            // Make redirect url
            JsonElement redirectUrlElement = obj.get(REDIRECT_URL_KEY);
            URL redirectUrl = null;
            try {
                redirectUrl = new URL(
                    redirectUrlElement.getAsJsonPrimitive().getAsString());
            } catch (MalformedURLException e) {
                throw new JsonParseException(e);
            }

            // Make redirect url
            JsonElement responseBodyElement = obj.get(RESPONSE_BODY_KEY);
            String responseBody = responseBodyElement.getAsJsonPrimitive().getAsString();

            return new BrowserAuthToken(
                cookieStrings, loginUrl, redirectUrl, responseBody);
        }

        @Override
        public JsonElement serialize(
            BrowserAuthToken token,
            Type type,
            JsonSerializationContext context) {

            // Make element from cookie strings
            JsonArray cookieStringsElement = new JsonArray();
            for (Cookie s : token.cookieStrings) {
                cookieStringsElement.add(context.serialize(s));
            }

            // Make element from login url
            JsonPrimitive loginUrlElement =
                new JsonPrimitive(token.loginUrl.toString());

            // Make element from redirect url
            JsonPrimitive redirectUrlElement =
                new JsonPrimitive(token.redirectUrl.toString());

            // Make element from redirect url
            JsonPrimitive responseBodyElement =
                new JsonPrimitive(token.responseBody);

            // Compose token element to return
            JsonObject tokenElement = new JsonObject();
            tokenElement.add(COOKIE_STRINGS_KEY, cookieStringsElement);
            tokenElement.add(LOGIN_URL_KEY, loginUrlElement);
            tokenElement.add(REDIRECT_URL_KEY, redirectUrlElement);
            tokenElement.add(RESPONSE_BODY_KEY, responseBodyElement);
            return tokenElement;
        }
    }

    private static final Gson GSON = new GsonBuilder()
        .registerTypeAdapter(byte[].class, new GsonSerializer())
        .create();

    /**
     * Maximum allowed number of cookie strings. Constant: {@value #MAX_COOKIE_STRINGS}
     */
    public static final int MAX_COOKIE_STRINGS = 256;

    /**
     * Maximum allowed length in bytes for each cookie string, once UTF-8 encoded. Constant:
     * {@value #MAX_COOKIE_STRING_LENGTH}
     */
    public static final int MAX_COOKIE_STRING_LENGTH = 1024;

    /**
     * Maximum allowed length in bytes for redirect URL, once turned into a String and UTF-8
     * encoded. Constant: {@value #MAX_REDIRECT_URL_LENGTH}
     */
    public static final int MAX_REDIRECT_URL_LENGTH = 1024;

    /**
     * Charset used when turning Strings into byte arrays.
     */
    public static final Charset STRING_CHARSET = Charset.forName("UTF-8");

    /**
     * Token type byte for this AuthToken subclass. Constant: {@value #TOKEN_TYPE_BYTE}
     */
    public static final byte TOKEN_TYPE_BYTE = 0x01;

    private final List<Cookie> cookieStrings;
    private final URL loginUrl;
    private final URL redirectUrl;
    private final String responseBody;

    /**
     * Constructor.
     *
     * @param cookieStrings Zero or more cookie strings to be inserted into the web browser.
     * @param loginUrl      The URL to log in using (using POST data).
     * @param redirectUrl   The URL to redirect the browser to afther successful authentication.
     * @param responseBody  The response body after successful login.
     */
    public BrowserAuthToken(
        final Collection<Cookie> cookieStrings,
        final URL loginUrl,
        final URL redirectUrl,
        final String responseBody) {
        // Verify the method's preconditions
        checkNotNull(cookieStrings, "BrowserAuthToken cannot have a null cookieStrings");

        this.cookieStrings = new ArrayList<Cookie>(cookieStrings);
        this.loginUrl = checkNotNull(loginUrl, "BrowserAuthToken cannot have a null loginUrl");
        this.redirectUrl = checkNotNull(redirectUrl, "BrowserAuthToken cannot have a null redirectUrl");
        this.responseBody = checkNotNull(responseBody, "BrowserAuthToken cannot have a null responseBody");
        ;
    }

    /**
     * Return a JSON encoded string representing this token. The string encodes a JSON object with
     * two keys: "cookieStrings", the value of which is a (possibly empty) list of cookie strings,
     * and "redirectUrl", the value of which is the redirect URL.
     * <p>
     * <p>
     * For example, calling getFull on a BrowserAuthToken instance with cookie strings "cookie1" and
     * "cookie2", and redirect URL "http://www.example.com" will yield the following JSON string:
     * <p>
     * <p>
     * <code>{"cookieStrings":["cookie1", "cookie2"],"redirectUrl":"http://wwww.example.com"}</code>
     */
    @Override
    public String getFull() {
        return GSON.toJson(this, BrowserAuthToken.class);
    }

    /**
     * Return the redirect URL component of the token.
     *
     * @return String representation off the instance's redirectUrl.
     */
    @Override
    public String getFallback() {
        return redirectUrl.toString();
    }

    /**
     * Once BrowserAuthToken instance is equal to another if they contain all the same cookie
     * strings and the same redirect URL.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof BrowserAuthToken) {
            BrowserAuthToken other = (BrowserAuthToken) obj;
            boolean cookiesEqual = cookieStrings.equals(other.cookieStrings);
            boolean urlEqual = redirectUrl.equals(other.redirectUrl);
            boolean responseBodyEqual = responseBody.equals(other.responseBody);

            return (cookiesEqual && urlEqual && responseBodyEqual);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(cookieStrings, loginUrl, redirectUrl, responseBody);
    }

    /**
     * Return this auth token encoded as a byte array. The format of the byte array is:
     * <ul>
     * <li>One byte identifying the AuthToken as a BrowserAuthToken (TOKEN_TYPE_BYTE)</li>
     * <li>Four bytes for an integer specifying the number of cookie strings</li>
     * <li>For each cookie string:</li>
     * <li><ul>
     * <li>The UTF-8 encoded URI associated with the cookie</li>
     * <li>The UTF-8 encoded cookie</li>
     * <li>The UTF-8 encoded datetime (RFC1123) when the server set the cookie</li>
     * </ul></li>
     * <li>The UTF-8 encoded login URL</li>
     * <li>The UTF-8 encoded redirect URL</li>
     * </ul>
     */
    @Override
    public byte[] toByteArray() throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final LengthPrependedDataOutputStream dos = new LengthPrependedDataOutputStream(baos);
        try {
            // Identify the type of AuthToken as a BrowserAuthToken
            dos.writeByte(BrowserAuthToken.TOKEN_TYPE_BYTE);

            // Number of cookie strings
            dos.writeInt(cookieStrings.size());

            // For each cookie string...
            for (Cookie c : cookieStrings) {
                final byte[] uriBytes = c.url.getBytes(STRING_CHARSET);
                final byte[] cookieBytes = c.value.getBytes(STRING_CHARSET);
                final byte[] dateBytes = c.date.getBytes(STRING_CHARSET);
                dos.writeVariableLengthByteArray(uriBytes);
                dos.writeVariableLengthByteArray(cookieBytes);
                dos.writeVariableLengthByteArray(dateBytes);
            }

            // Similar for login url
            final byte[] loginUrlBytes =
                loginUrl.toString().getBytes(STRING_CHARSET);
            dos.writeVariableLengthByteArray(loginUrlBytes);

            // Similar for redirect url
            final byte[] redirectUrlBytes =
                redirectUrl.toString().getBytes(STRING_CHARSET);
            dos.writeVariableLengthByteArray(redirectUrlBytes);

            // Similar for response body
            final byte[] responseBodyBytes =
                responseBody.getBytes(STRING_CHARSET);
            dos.writeVariableLengthByteArray(responseBodyBytes);

            return baos.toByteArray();
        } finally {
            dos.close();
        }
    }

    /**
     * Reconstruct a BrowserAuthToken instance from a byte array produced by {@link #toByteArray()}.
     * The following expression will always evaluate to <code>true</code>:
     * <p>
     * <p>
     * <code>token.equals(BrowserAuthToken.fromByteArray(token.toByteArray()));</code>
     * <p>
     * <p>
     * where <code>token</code> is a BrowserAuthToken instance.
     *
     * @param bytes byte array containing an encoded BrowserAuthToken.
     * @return reconstructed BrowserAuthToken instance.
     * @throws IOException if the token type byte is invalid or the token has been incorrectly
     *                     serialised.
     */
    public static BrowserAuthToken fromByteArray(final byte[] bytes)
        throws IOException {
        // Verify the method's preconditions
        checkNotNull(bytes, "BrowserAuthToken fromByteArray bytes param cannot be null");

        final ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        final LengthPrependedDataInputStream dis =
            new LengthPrependedDataInputStream(bais);
        try {
            // Verify the AuthToken type is correct
            final byte tokenTypeByte = dis.readByte();
            if (tokenTypeByte != TOKEN_TYPE_BYTE) {
                throw new IOException(
                    "Read token type byte (" + tokenTypeByte +
                        ") did not match BrowserAuthToken.TOKEN_TYPE_BYTE (" +
                        TOKEN_TYPE_BYTE + ")");
            }

            // Number of cookie strings
            final int cookieStringsLength = dis.readInt();
            final List<Cookie> cookieStrings =
                new ArrayList<Cookie>(cookieStringsLength);

            // For each cookie string...
            for (int i = 0; i < cookieStringsLength; i++) {
                final String uri = new String(
                    dis.readVariableLengthByteArray(), STRING_CHARSET);
                final String cookie = new String(
                    dis.readVariableLengthByteArray(), STRING_CHARSET);
                final String date = new String(
                    dis.readVariableLengthByteArray(), STRING_CHARSET);
                cookieStrings.add(new Cookie(uri, cookie, date));
            }

            // Similar for login url
            final URL loginUrl = new URL(
                new String(dis.readVariableLengthByteArray(),
                    STRING_CHARSET));

            // Similar for redirect url
            final URL redirectUrl = new URL(
                new String(dis.readVariableLengthByteArray(),
                    STRING_CHARSET));

            // Similar for response body
            final String responseBody =
                new String(dis.readVariableLengthByteArray(), STRING_CHARSET);

            return new BrowserAuthToken(cookieStrings, loginUrl, redirectUrl, responseBody);
        } finally {
            dis.close();
        }
    }
}