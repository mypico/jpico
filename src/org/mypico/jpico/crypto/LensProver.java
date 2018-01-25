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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.DestroyFailedException;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.FormElement;
import org.jsoup.select.Elements;
import org.mypico.jpico.crypto.ContinuousProver.ProverStateChangeNotificationInterface;
import org.mypico.jpico.crypto.ContinuousProver.SchedulerInterface;
import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImp;
import org.mypico.jpico.data.session.SessionImpFactory;
import org.mypico.jpico.util.PicoCookieManager;
import org.mypico.jpico.util.WebProverUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;

/**
 * Performs the authentication protocol for the prover (Pico) when interacting with the Pico Lens
 * and a service that the Pico is logging in to.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
final public class LensProver implements Prover {

    private final static Logger LOGGER =
        LoggerFactory.getLogger(LensProver.class.getSimpleName());
    // @see https://code.google.com/p/android/issues/detail?id=24672
    private boolean isDestroyed;

    private final LensPairing pairing;
    private final URI loginUri;
    private final SessionImpFactory sessionFactory;
    private final PicoCookieManager cookieManager;
    private final Document loginForm;
    private final String cookieString;

    /**
     * Constructor.
     *
     * @param pairing        The pairing between the Pico and the service.
     * @param loginUri       The URI where the Pico should POST data to in order to authenticate to the
     *                       service.
     * @param loginForm      The POST data to be sent to the login form to authenticate to the service.
     * @param cookieString   The cookie to be passed back to the Pico Lens to allow access to the
     *                       service through the web browser.
     * @param sessionFactory A session factory which produces concrete {@link SessionImp} instances.
     */
    public LensProver(
        final LensPairing pairing,
        final URI loginUri,
        final String loginForm,
        final String cookieString,
        final SessionImpFactory sessionFactory) {

        // Verify the method's preconditions
        this.pairing = Preconditions.checkNotNull(pairing,
            "LensProver cannot have a null pairing");
        this.loginUri = Preconditions.checkNotNull(loginUri,
            "LensProver cannot have a null loginUri");
        Preconditions.checkNotNull(loginForm,
            "LensProver cannot have a null loginForm");
        this.loginForm = Jsoup.parseBodyFragment(loginForm, loginUri.toString());
        this.cookieString = Preconditions.checkNotNull(cookieString,
            "LensProver cannot have a null cookieString");
        this.sessionFactory = Preconditions.checkNotNull(sessionFactory,
            "LensProver cannot have a null session factory");

        // Set cookie handler, keeping reference to cookieManager so we can get
        // back the cookies to build the auth token.
        cookieManager = new PicoCookieManager();
        cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(cookieManager);
    }

    @Override
    public ContinuousProver getContinuousProver(
        final Session session,
        final ProverStateChangeNotificationInterface notificationInterface,
        final SchedulerInterface schedulerInterface) {
        throw new UnsupportedOperationException(
            "Lens pairings do not support continuous authentication");
    }

    @Override
    public Session startSession() throws CryptoRuntimeException {
        try {
            // Get the login form         
            final FormElement loginForm =
                WebProverUtils.getLoginForm(this.loginForm);

            // Build the post data for the form submission
            final String postData = WebProverUtils.buildPostData(
                loginForm, pairing.getCredentials());

            // Make form submission POST request
            final URL connUrl = loginForm.submit().request().url();
            LOGGER.debug("Making form submission to {}", connUrl);

            // Do not follow any further redirects, we can now
            // pass back the data the Browser needs to complete the job
            final HttpURLConnection loginConnection =
                WebProverUtils.makeRequest(connUrl, loginUri.toURL(), postData, cookieString);
            URL redirectUrl = WebProverUtils.getRedirectUrl(loginConnection);
            if (redirectUrl == null) {
                redirectUrl = connUrl;
            }

            StringBuffer sb = new StringBuffer();
            // Read the response body
            if (loginConnection.getResponseCode() == 200) {

                if (loginConnection.getInputStream() != null) {
                    BufferedReader br = new BufferedReader(new InputStreamReader((loginConnection.getInputStream())));
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line);
                    }
                }
                LOGGER.trace("Response body = {}", sb.toString());
            }
            LOGGER.trace("Response body = {}", sb.toString());

            // Make browser auth token result
            final AuthToken token = new BrowserPasswordAuthToken(
                cookieManager.getRawCookies(),
                loginUri.toURL(),
                redirectUrl,
                sb.toString(),
                pairing.getCredentials());

            // New closed session with null remote ID
            return Session.newInstanceClosed(
                sessionFactory, null, pairing, token);
        } catch (IOException e) {
            LOGGER.error("IOException occurred!", e);
            // Return Session in error state
            return Session.newInstanceInError(
                sessionFactory, pairing, Session.Error.IO_EXCEPTION);
        } finally {
            // Remove the stored cookies
            CookieStore store = cookieManager.getCookieStore();
            store.removeAll();
        }
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (isDestroyed) {
            throw new IllegalStateException("Already destroyed");
        }
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }
}


