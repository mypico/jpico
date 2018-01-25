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

import java.net.URL;
import java.util.Collection;
import java.util.Map;

/**
 * Adds simply displaying the stored passwords as a fallback.
 * <p>
 * The passwords are not sent by the byte or json serialisers.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public class BrowserPasswordAuthToken extends BrowserAuthToken {

    private final Map<String, String> formFields;

    /**
     * Constructor.
     *
     * @param cookieStrings Zero or more cookie strings to be inserted into the web browser.
     * @param loginUrl      The URL to log in using (using POST data).
     * @param redirectUrl   The URL to redirect the browser to afther successful authentication.
     * @param responseBody  The response body after successful login.
     * @param formFields    The fields for constructing the form data to POST.
     */
    public BrowserPasswordAuthToken(
        final Collection<Cookie> cookieStrings,
        final URL loginUrl,
        final URL redirectUrl,
        final String responseBody,
        final Map<String, String> formFields) {
        super(cookieStrings, loginUrl, redirectUrl, responseBody);
        this.formFields = formFields;
    }

    /**
     * For a Password Auth token, the fallback is simply the username and password displayed to the
     * user, as session cookies are unlikely to be transcribable.
     * <p>
     * This sacrifices the benefit of never revealing the long term tokens to the terminal.
     */
    @Override
    public String getFallback() {

        final StringBuilder fallBackString = new StringBuilder();
        for (Map.Entry<String, String> pair : formFields.entrySet()) {
            fallBackString.append(pair.getKey());
            fallBackString.append(": ");
            fallBackString.append(pair.getValue());
            fallBackString.append('\n');
        }
        return fallBackString.toString();
    }
}
