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


package org.mypico.jpico.data.pairing;

import java.util.Map;
import java.util.List;

/**
 * Interface of concrete implementations underlying {@link LensPairing} instances.
 * <p>
 * <p>
 * This interface is part of a <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge
 * pattern</a>. Each <code>LensPairing</code> instance has a reference to a concrete
 * {@link LensPairingImp} instance. See {@link org.mypico.jpico.test.data.pairing} package documentation
 * for more information on this pattern.
 *
 * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
 * @see LensPairing
 * @see LensPairingImpFactory
 */
public interface LensPairingImp extends PairingImp {

    /**
     * Get the credentials for the pairing.
     * <p>
     * This is a dictionary of key-value pairs used to construct the POST data for logging in to
     * the service. It's essentially the form fields needed to log in (including username and
     * password).
     *
     * @return the credentials for the pairing.
     */
    Map<String, String> getCredentials();

    /**
     * A list of the private fields in the credential database.
     * <p>
     * This is a list of keys. If one of the keys for a key-value pair output by
     * {@link #getCredentials()} is in this list, then the value should be considered
     * confidential, so shouldn't be displayed by the UI. For example, it could be the user's
     * password.
     *
     * @return A list of the private credential keys.
     */
    List<String> getPrivateFields();
}
