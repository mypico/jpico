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

import static com.google.common.base.Preconditions.checkNotNull;

import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.mypico.jpico.comms.org.apache.commons.codec.binary.Base64;

/**
 * Some simple hashing utility functions.
 *
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
final public class HashUtils {

    private static final MessageDigest sha256;
    private static final Charset utf8;

    static {
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No SHA-256 algorithm available", e);
        }
        try {
            utf8 = Charset.forName("UTF-8");
        } catch (UnsupportedCharsetException e) {
            throw new RuntimeException("UTF-8 encoding not available", e);
        }
    }

    /**
     * UTF-8 encode then SHA-256 hash a {@link String}.
     *
     * @param str input string.
     * @return SHA-256 hash of the UTF-8 encoding of <code>str</code>
     */
    public static byte[] sha256(final String str) {
        checkNotNull(str, "input string cannot be null");

        sha256.reset();
        sha256.update(str.getBytes(utf8));
        return sha256.digest();
    }

    /**
     * UTF-8 encode, SHA-256 hash, then base 64 encode a {@link String}.
     *
     * @param str input string.
     * @return base 64 encoding of the SHA-256 hash of the UTF-8 encoding of <code>str</code>
     */
    public static String base64Sha256(final String str) {
        return Base64.encodeBase64String(sha256(str));
    }

    /**
     * Binary encode then SHA-256 hash a {@link Key} instance and return the raw byte array. To
     * binary encoded <code>key</code> this method calls the {@link Key#getEncoded() getEncoded}
     * method which returns the key encoded as a byte array using some standard format (typically
     * DER ASN.1).
     *
     * @param key the Key instance to hash
     * @return SHA-256 hash of the binary encoding of <code>key</code>
     */
    public static byte[] sha256Key(final Key key) {
        checkNotNull(key);

        sha256.reset();
        sha256.update(key.getEncoded());
        return sha256.digest();
    }

    /**
     * Binary encode, SHA-256 hash, then base 64 encode a {@link Key} instance. To binary encoded
     * <code>key</code> method calls the {@link Key#getEncoded() getEncoded} method which returns
     * the key encoded as a byte array using some standard format (typically DER ASN.1).
     *
     * @param key the Key instance to hash
     * @return base 64 encoding of the SHA-256 hash of the binary encoding of <code>key</code>
     */
    public static String base64Sha256Key(final Key key) {
        return Base64.encodeBase64String(sha256Key(key));
    }
}
