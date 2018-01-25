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

import java.io.IOException;

/**
 * Factory for reconstructing serialised AuthToken instances.
 *
 * @author Graeme Jenkinson &lt;gcj21@cl.cam.ac.uk&gt;
 */
final public class AuthTokenFactory {

    /**
     * Reconstruct and AuthToken from a byte array.
     *
     * @param bytes AuthToken as a byte array.
     * @return AuthToken instance.
     * @throws IOException if the token type byte is not recognised of the token has been
     *                     incorrectly serialised.
     */
    public static AuthToken fromByteArray(final byte[] bytes)
        throws IOException {

        final byte tokenTypeByte = bytes[0];

        if (tokenTypeByte == BrowserAuthToken.TOKEN_TYPE_BYTE) {
            return BrowserAuthToken.fromByteArray(bytes);
        } else if (tokenTypeByte == SimpleAuthToken.TOKEN_TYPE_BYTE) {
            return SimpleAuthToken.fromByteArray(bytes);
        } else {
            throw new IOException(
                "Unrecognised token type byte (" + tokenTypeByte + ")");
        }
    }
}
