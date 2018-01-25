package org.mypico.jpico.util;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jsoup.Connection;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.FormElement;
import org.jsoup.select.Elements;
import org.mypico.jpico.crypto.Cookie;
import org.mypico.jpico.crypto.LensProver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class containing a variety of tools useful for authenticating to websites.
 */
public class WebProverUtils {
    private final static Logger LOGGER =
        LoggerFactory.getLogger(LensProver.class.getSimpleName());
    private final static String INPUT_TYPE_PASSWORD =
        "input[type=password]";
    private final static String ACCEPT_ENCODING = "";
    private final static String USER_AGENT =
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:27.0) Gecko/20100101 "
            + "Firefox/27.0";
    private final static String CONTENT_TYPE =
        "application/x-www-form-urlencoded";


    private static class PostStringBuilder {

        private final StringBuilder b = new StringBuilder();

        @Override
        public String toString() {
            return b.toString();
        }

        void add(final String key, final String value) {
            // Verify the method's preconditions
            assert (key != null);
            assert (value != null);

            try {
                if (b.length() > 0) {
                    b.append("&");
                }
                b.append(URLEncoder.encode(key, "UTF-8"));
                b.append("=");
                b.append(URLEncoder.encode(value, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 not supported", e);
            }
        }
    }

    /**
     * Build the login form POST data string. This method takes the login form {@link FormElement}
     * and the saved pairing credentials and produces the appropriate POST data string.
     * <p>
     * <p>
     * For each <code>input</code> login form element:
     * <ul>
     * <li>If its <code>name</code> appears in the <code>credentials</code> map, it is included in
     * the POST data with the corresponding value in the map.
     * <li>If its <code>type</code> is <code>hidden</code>, it is included in the POST data with its
     * own HTML <code>value</code>.
     * <li>Otherwise it is ignored.</li>
     * </ul>
     * <p>
     * <p>
     * The final case is so that names and values of checkboxes, radio buttons, submit buttons and
     * other elements are not submitted, if they were not saved during the initial pairing.
     *
     * @param loginForm   the form elements that make up the login form.
     * @param credentials the credential key-value pairs stored by Pico.
     * @return the resulting POST data string.
     */
    public static String buildPostData(
        final FormElement loginForm,
        final Map<String, String> credentials) {
        // Verify the method's preconditions
        assert (loginForm != null);
        assert (credentials != null);

        final PostStringBuilder builder = new PostStringBuilder();

        final List<Connection.KeyVal> data = loginForm.formData();
        for (Connection.KeyVal kv : data) {
            final String k = kv.key();
            String v = null;
            if (!credentials.containsKey(k)) {
                final Element inputElement =
                    loginForm.select("input[name=" + k + "]").first();
                if (inputElement != null &&
                    inputElement.attr("type").equals("hidden")) {
                    LOGGER.debug("Form field with name {} is hidden", k);
                    v = kv.value();
                } else {
                    // Ignore the field -- We don't want things like unchecked
                    // checkbox fields, submit buttons etc. from being added to
                    // the request post data.
                    v = null;
                }
            }

            if (v != null) {
                LOGGER.debug("Setting {}={}", k, v);
                builder.add(k, v);
            } else {
                LOGGER.debug("Ignoring {}", k);
                // Nothing added to post data
            }
        }

        for (Map.Entry<String, String> entry : credentials.entrySet()) {
            String k = entry.getKey();
            String v = entry.getValue();
            LOGGER.debug("Setting credentials {}={}", k, v);
            builder.add(k, v);
        }

        return builder.toString();
    }

    /**
     * Get the location that an HTTP redirect message redirects to.
     *
     * @param connection The originally HTTP request connection.
     * @return the redirect location.
     * @throws IOException thrown if there is an error, such as the redirect URL being malformed.
     */
    public static URL getRedirectUrl(final HttpURLConnection connection)
        throws IOException {
        // Verify the method's preconditions
        assert (connection != null);

        final int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_MOVED_PERM ||
            responseCode == HttpURLConnection.HTTP_MOVED_TEMP ||
            responseCode == HttpURLConnection.HTTP_SEE_OTHER) {
            final String locationHeader =
                connection.getHeaderField("Location");
            if (locationHeader != null) {
                try {
                    return new URL(locationHeader);
                } catch (MalformedURLException e) {
                    // Location header may contain a relative URL
                    try {
                        return new URL(connection.getURL(), locationHeader);
                    } catch (MalformedURLException ex) {
                        LOGGER.error(
                            "Malformed redirect location: {}", locationHeader);
                        throw new IOException("Malformed redirect location: {}" +
                            locationHeader);
                    }
                }
            } else {
                LOGGER.warn(
                    "Response had a redirect response code, " +
                        "but no Location header");
                throw new IOException(
                    "Response had a redirect response code," +
                        "but no Location header");
            }
        } else {
            if (responseCode != HttpURLConnection.HTTP_OK) {
                LOGGER.warn("Response was not a redirect or OK");
                throw new IOException("Response was not a redirect or OK");
            }
            return null;
        }
    }

    /**
     * Get the contents of the login form from a larger HTML document.
     *
     * @param loginPage The larger HTML document containing the login form.
     * @return the login form found on the page, if there is one.
     * @throws IOException if there is no login form on the page.
     */
    public static FormElement getLoginForm(final Document loginPage)
        throws IOException {
        // Verify the method's preconditions
        assert (loginPage != null);

        final Elements forms = loginPage.select("form");
        if (!forms.isEmpty()) {
            FormElement loginForm = null;
            int numLoginForms = 0;

            for (final Element form : forms) {
                LOGGER.trace("Checking form for password fields");
                final Elements passwordFields =
                    form.select(INPUT_TYPE_PASSWORD);
                if (!passwordFields.isEmpty()) {
                    ++numLoginForms;
                    if (loginForm == null) {
                        loginForm = (FormElement) form;
                    }
                }
            }

            if (numLoginForms == 0) {
                LOGGER.warn("No forms with password fields found");
                throw new IOException("No forms with password fields found");
            } else if (numLoginForms > 1) {
                LOGGER.warn(
                    "Multiple forms with password fields found, first one "
                        + "returned");
            } else {
                LOGGER.debug("Found single form with password field {}",
                    loginForm);
            }

            return loginForm;
        } else {
            LOGGER.warn("No forms found!");
            LOGGER.trace("Login page content: {}", loginPage.html());
            throw new IOException("No forms found");
        }
    }

    /**
     * Returns a string containing the tokens joined by delimiters.
     * <p>
     * For n tokens, (n - 1) delimeters will be added; so no delimiter is added before the first or
     * after the last token.
     *
     * @param delimiter the delimeter to add between each tokens.
     * @param tokens    an array objects to be joined. Strings will be formed from the objects by
     *                  calling object.toString().
     * @return The resulting string of tokens and delimiters combined.
     */
    public static String join(CharSequence delimiter, Iterable<?> tokens) {
        StringBuilder sb = new StringBuilder();
        boolean firstTime = true;
        for (Object token : tokens) {
            if (firstTime) {
                firstTime = false;
            } else {
                sb.append(delimiter);
            }
            sb.append(token);
        }
        return sb.toString();
    }

    /**
     * Make an HTTP request.
     *
     * @param url          The URL to make the request to.
     * @param referer      The refer value to pass on to the server serving the URL.
     * @param postData     The HTTP POST data to include with the request.
     * @param cookieString The cookies to include with the request.
     * @return The HTTP connection made.
     * @throws IOException in case there's an error connecting to the site.
     */
    public static HttpURLConnection makeRequest(
        final URL url, final URL referer, final String postData, final String cookieString)
        throws IOException {

        // Verify the method's preconditions
        assert (url != null);
        assert (referer != null);
        assert (postData != null);

        LOGGER.debug("Making request to {}", url);
        final HttpURLConnection connection =
            (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);

        // Set other request headers
        connection.setRequestProperty("Accept-Encoding", ACCEPT_ENCODING);
        connection.setRequestProperty("Cookie", cookieString);

        connection.setRequestProperty("User-Agent", USER_AGENT);
        if (referer != null) {
            connection.setRequestProperty("Referer", referer.toString());
        }

        // Write post data
        if (postData != null) {

            LOGGER.trace("Request POST data: {}", postData);
            final byte[] postBytes = postData.getBytes("UTF-8");
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", CONTENT_TYPE);
            connection.setRequestProperty(
                "Content-length", Integer.toString(postBytes.length));

            LOGGER.trace(
                "Request headers: {}", connection.getRequestProperties());

            connection.setDoOutput(true);
            OutputStream os = null;
            try {
                os = connection.getOutputStream();
                os.write(postBytes);
                os.flush();
            } finally {
                if (os != null) {
                    os.close();
                }
            }
        } else {
            LOGGER.trace(
                "Request headers: {}", connection.getRequestProperties());
        }

        // Make the request
        connection.connect();

        LOGGER.debug("Response code: {}", connection.getResponseCode());
        LOGGER.trace("Response headers: {}", connection.getHeaderFields());

        return connection;
    }
}
