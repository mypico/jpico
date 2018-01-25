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


package org.mypico.jpico.crypto.messages;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.util.LengthPrependedDataInputStream;

/**
 * Encrypted form of an {@link PicoAuthMessage}.
 * <p>
 * <p>An <code>EncAuthMessage</code> contains one cleartext item:
 * <ul>
 * <li><code>sessionId</code></li>
 * </ul>
 * <p>
 * <p>The encrypted items are encrypted using an AES cipher in Gallois counter mode, using the Pico's
 * symmetric session encryption key. The format of encrypted items is as follows:
 * <p>
 * <p><code>l||signature||m||mac</code>
 * <p>
 * <p>Where:
 * <ul>
 * <li><code>l</code> and <code>m</code> are four-byte (big-endian) integers specifying the length
 * (in bytes) of the next item.</li>
 * <li><code>signature</code> and <code>mac</code> are items of the corresponding unencrypted
 * {@link PicoAuthMessage}.</li>
 * </ul>
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see PicoAuthMessage
 */
public final class EncPicoAuthMessage extends EncryptedMessage<PicoAuthMessage> {

    /**
     * Constructor.
     *
     * @param sessionId     The session id.
     * @param encryptedData The data to encrypt.
     * @param iv            The iv to use for encryption.
     */
    EncPicoAuthMessage(int sessionId, byte[] encryptedData, byte[] iv) {
        super(sessionId, encryptedData, iv);
    }

    @Override
    protected PicoAuthMessage createUnencryptedMessage(LengthPrependedDataInputStream is)
        throws IOException, FieldDeserializationException {
        // Read raw bytes from input stream
        byte[] picoPublicKeyBytes = is.readVariableLengthByteArray();
        byte[] signature = is.readVariableLengthByteArray();
        byte[] mac = is.readVariableLengthByteArray();
        byte[] extraData = is.readVariableLengthByteArray();

        KeyFactory kf = CryptoFactory.INSTANCE.ecKeyFactory();
        PublicKey picoPublicKey;
        try {
            picoPublicKey = kf.generatePublic(new X509EncodedKeySpec(picoPublicKeyBytes));
        } catch (InvalidKeySpecException e) {
            // Thrown when the key bytes don't form a valid key spec -- the key cannot be
            // deserialized.
            throw new FieldDeserializationException(e);
        }

        return new PicoAuthMessage(sessionId, picoPublicKey, signature, mac, extraData);
    }
}
