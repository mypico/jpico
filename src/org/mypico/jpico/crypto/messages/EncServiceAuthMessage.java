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
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.crypto.util.LengthPrependedDataInputStream;

/**
 * Encrypted form of a {@link ServiceAuthMessage}.
 * <p>
 * An <code>EncServiceAuthMessage</code> contains three cleartext items:
 * <ul>
 * <li><code>sessionId</code></li>
 * <li><code>serviceEphemeralPublicKey</code></li>
 * <li><code>serviceNonce</code></li>
 * </ul>
 * <p>
 * The <code>encryptedData</code> is encrypted using an AES cipher in Gallois counter mode, using
 * the service's symmetric session encryption key. The format of encrypted items is as follows:
 * <p>
 * <code>l||servicePublicKey||m||signature||n||mac</code>
 * <p>
 * Where:
 * <ul>
 * <li><code>l</code>, <code>m</code> and <code>n</code> are all four-byte (big-endian) integers
 * specifying the length (in bytes) of the next item.</li>
 * <li><code>servicePublicKey</code> is the long term public key of the Pico encoded in the X.509
 * binary encoding format.</li>
 * <li><code>signature</code> and <code>mac</code> are items of the corresponding unencrypted
 * {@link ServiceAuthMessage}.</li>
 * </ul>
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see org.mypico.jpico.crypto.messages.ServiceAuthMessage
 */
public final class EncServiceAuthMessage extends EncryptedMessage<ServiceAuthMessage> {

    private final PublicKey serviceEphemPublicKey;
    private final Nonce serviceNonce;

    /**
     * Constructor.
     *
     * @param sessionId                 The session id.
     * @param serviceEphemeralPublicKey The service's ephemeral key.
     * @param serviceNonce              The service nonce.
     * @param encryptedData             The data to encrypt.
     * @param iv                        The iv to use for encryption.
     */
    EncServiceAuthMessage(int sessionId, PublicKey serviceEphemeralPublicKey,
                          Nonce serviceNonce, byte[] encryptedData, byte[] iv) {
        super(sessionId, encryptedData, iv);
        this.serviceEphemPublicKey = serviceEphemeralPublicKey;
        this.serviceNonce = serviceNonce;
    }

    /**
     * Get the service's ephemeral public key.
     *
     * @return the public key.
     */
    public PublicKey getServiceEphemeralPublicKey() {
        return serviceEphemPublicKey;
    }

    /**
     * Get the service nonce.
     *
     * @return the nonce.
     */
    public Nonce getServiceNonce() {
        return serviceNonce;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof EncServiceAuthMessage) {
            EncServiceAuthMessage other = (EncServiceAuthMessage) obj;
            return (serviceEphemPublicKey
                .equals(other.serviceEphemPublicKey))
                && (serviceNonce.equals(other.serviceNonce))
                && super.equals(other);
        } else {
            return false;
        }
    }

    @Override
    protected ServiceAuthMessage createUnencryptedMessage(
        LengthPrependedDataInputStream dis) throws IOException, FieldDeserializationException {
        // Read the following fields: servicePublicKey||signature||mac
        byte[] servicePublicKeyBytes = dis.readVariableLengthByteArray();
        byte[] signature = dis.readVariableLengthByteArray();
        byte[] mac = dis.readVariableLengthByteArray();

        // Create the PublicKey object from the encoded bytes
        KeyFactory kf = CryptoFactory.INSTANCE.ecKeyFactory();
        PublicKey servicePublicKey;
        try {
            servicePublicKey = kf.generatePublic(new X509EncodedKeySpec(servicePublicKeyBytes));
        } catch (InvalidKeySpecException e) {
            throw new EncryptedMessage.FieldDeserializationException(e);
        }

        return new ServiceAuthMessage(
            sessionId, serviceEphemPublicKey, serviceNonce, servicePublicKey, signature, mac);
    }
}
