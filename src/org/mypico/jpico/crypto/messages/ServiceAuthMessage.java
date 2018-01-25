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

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.crypto.util.LengthPrependedDataOutputStream;

import com.google.common.base.Objects;

/**
 * The second message of the SIGMA-I protocol, which is sent from the service to the Pico to
 * authenticate the service to the Pico.
 * <p>
 * <p>
 * A <code>ServiceAuthMessage</code> contains six items:
 * <ul>
 * <li><code>sessionId</code> - An integer identifying the current session.</li>
 * <li><code>serviceEphemeralPublicKey</code> - A Diffie-Hellman exponential which will be combined
 * with another one from the Pico to form the symmetric keys for this session.</li>
 * <li><code>serviceNonce</code> - A nonce to ensure freshness of the Pico's response.</li>
 * <li><code>servicePublicKey</code> - The long-term public key of the service.</li>
 * <li><code>signature</code> - SIGMA-specific signature component (see below).</li>
 * <li><code>mac</code> - SIGMA-specific mac component (see below).</li>
 * </ul>
 * <p>
 * <p>
 * <code>signature</code> is formed by taking the SHA-256 hash of the following and signing it using
 * the service's long-term private key:
 * <p>
 * <code>picoNonce||sessionId||serviceEphemeralPublicKey</code>
 * <p>
 * Where:
 * <ul>
 * <li><code>sessionId</code> is a single four-byte (big-endian) integer.</li>
 * <li><code>serviceEphemeralPublicKey</code> is encoded in the X.509 binary encoding format.</li>
 * </ul>
 * <p>
 * <p>
 * <code>mac</code> is the service's long term public key, HMAC'd using the service's session MAC
 * key.
 * <p>
 * <p>
 * The next message in the protocol is {@link PicoAuthMessage}.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see org.mypico.jpico.crypto.messages.EncServiceAuthMessage
 */
public final class ServiceAuthMessage extends UnencryptedMessage<EncServiceAuthMessage> {

    private final PublicKey serviceEphemeralPublicKey;
    private final Nonce serviceNonce;
    private final PublicKey serviceIdentityPublicKey;
    private final byte[] signature;
    private final byte[] mac;

    ServiceAuthMessage(int sessionId, PublicKey serviceEphemeralPublicKey,
                       Nonce serviceNonce, PublicKey servicePublicKey, byte[] signature,
                       byte[] mac) {
        super(sessionId);

        this.serviceEphemeralPublicKey = checkNotNull(serviceEphemeralPublicKey, "serviceEphemeralPublicKey cannot be null");
        this.serviceNonce = checkNotNull(serviceNonce, "serviceNonce cannot be null");
        this.serviceIdentityPublicKey = checkNotNull(servicePublicKey, "servicePublicKey cannot be null");
        this.signature = checkNotNull(signature, "signature cannot be null");
        this.mac = checkNotNull(mac, "mac cannot be null");
    }

    /**
     * Gets the session id assigned by the service to allow the reply to the service to correlate
     * the ServiceAuthMessage it sent with the replying PicoAuthMessage e.g. when using HTTP as the
     * transport mechanism.
     *
     * @return The session id.
     */
    public int getSessionId() {
        return sessionId;
    }

    /**
     * Get the ephemeral public key of the service. This key is generated per-session.
     *
     * @return the service's ephemeral public key.
     */
    public PublicKey getServiceEphemeralPublicKey() {
        return serviceEphemeralPublicKey;
    }

    /**
     * Get the nonce used for this session.
     *
     * @return the session nonce.
     */
    public Nonce getServiceNonce() {
        return serviceNonce;
    }

    /**
     * Get the long term identity public key of the service.
     *
     * @return the long term identity public key of the service.
     */
    public PublicKey getServicePublicKey() {
        return serviceIdentityPublicKey;
    }

    /**
     * Get the message signature, used to prove it was sent by the service.
     *
     * @return the message signature.
     */
    public byte[] getSignature() {
        return signature;
    }

    /**
     * Get the message authentication code, used to demonstrate the integrity of the message.
     *
     * @return the MAC.
     */
    public byte[] getMac() {
        return mac;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ServiceAuthMessage) {
            ServiceAuthMessage other = (ServiceAuthMessage) obj;
            return (sessionId == other.sessionId)
                && Arrays.equals(serviceEphemeralPublicKey.getEncoded(),
                other.serviceEphemeralPublicKey.getEncoded())
                && serviceNonce.equals(other.serviceNonce)
                && Arrays.equals(serviceIdentityPublicKey.getEncoded(),
                other.serviceIdentityPublicKey.getEncoded())
                && Arrays.equals(signature, other.signature)
                && Arrays.equals(mac, other.mac);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sessionId, serviceEphemeralPublicKey, serviceNonce, serviceIdentityPublicKey,
            signature, mac);
    }

    /**
     * Obviously not the entire message can be signed (e.g. the signature isn't signed). This
     * method takes the data elements, turns them into a data stream and then signs the resulting
     * stream of data.
     *
     * @param picoNonce                 The session nonce.
     * @param sessionId                 The session id.
     * @param serviceEphemeralPublicKey The ephemeral public key of the verifier (service).
     * @return the signed data.
     */

    public static byte[] getBytesToSign(
        final Nonce picoNonce,
        final int sessionId,
        final PublicKey serviceEphemeralPublicKey) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.write(picoNonce.getValue());
            dos.writeInt(sessionId);
            dos.write(serviceEphemeralPublicKey.getEncoded());
        } catch (IOException e) {
            // Exception is re-thrown because a ByteArrayOutputStream specifically cannot raise
            // IOExceptions.
            throw new RuntimeException(e);
        }
        return baos.toByteArray();
        /*
        final byte[] bytesToSign;

        byte[] picoNonceBytes = picoNonce.getValue();
        byte[] sessionIdBytes = ByteBuffer.allocate(4).putInt(sessionId).array();
        byte[] serviceEphemeralPublicKeyBytes = serviceEphemeralPublicKey.getEncoded();
        int numBytes =
                picoNonceBytes.length + sessionIdBytes.length
                        + serviceEphemeralPublicKeyBytes.length;

        ByteBuffer byteBuffer = ByteBuffer.allocate(numBytes);
        byteBuffer.put(picoNonceBytes);
        byteBuffer.put(sessionIdBytes);
        byteBuffer.put(serviceEphemeralPublicKeyBytes);

        bytesToSign = byteBuffer.array();
        return bytesToSign;
        */
    }

    /**
     * Creates a ServiceAuthMessage, using the provided keys to link the ephemeral keys to the
     * service's long term key.
     *
     * @param sessionId                 Identifies the session to the service
     * @param serviceEphemeralPublicKey The verifier's ephemeral public key for the session.
     * @param serviceNonce              The nonce sent as part of the message.
     * @param picoNonce                 The pico nonce
     * @param serviceIdentityKey        The service long term identity key to use for signing the message.
     * @param serviceMacKey             is one of the derived keys from the DH Key agreement.
     * @return The resulting {@code ServiceAuthMessage} generated.
     * @throws InvalidKeyException if one of the supplied keys is not valid.
     * @throws SignatureException  if the signature cannot be created with the supplied arguments.
     */
    public static ServiceAuthMessage getInstance(int sessionId,
                                                 PublicKey serviceEphemeralPublicKey, Nonce serviceNonce,
                                                 Nonce picoNonce, KeyPair serviceIdentityKey, SecretKey serviceMacKey) throws InvalidKeyException, SignatureException {

        PublicKey serviceIdentityPublicKey = serviceIdentityKey.getPublic();
        PrivateKey serviceIdentityPrivateKey = serviceIdentityKey.getPrivate();

        // Get the bytes to be signed:
        // picoNonce||sessionId||serviceEphemeralPublicKey
        byte[] bytesToSign = getBytesToSign(picoNonce, sessionId, serviceEphemeralPublicKey);

        // Sign using the service's long-term private key:
        Signature signer = CryptoFactory.INSTANCE.sha256Ecdsa();
        signer.initSign(serviceIdentityPrivateKey);
        signer.update(bytesToSign);
        byte[] signature = signer.sign();

        // Make the MAC of the service's long-term public key, using the
        // service's MAC key for this session:
        Mac macer = CryptoFactory.INSTANCE.sha256Hmac();
        macer.init(serviceMacKey);
        byte[] mac = macer.doFinal(serviceIdentityPublicKey.getEncoded());

        return new ServiceAuthMessage(sessionId, serviceEphemeralPublicKey,
            serviceNonce, serviceIdentityPublicKey, signature, mac);
    }

    @Override
    protected EncServiceAuthMessage createEncryptedMessage(
        byte[] encryptedData, byte[] iv) {
        // TODO Auto-generated method stub
        return new EncServiceAuthMessage(sessionId, serviceEphemeralPublicKey,
            serviceNonce, encryptedData, iv);
    }

    @Override
    protected void writeDataToEncrypt(LengthPrependedDataOutputStream los) throws IOException {
        byte[] servicePublicKeyBytes = serviceIdentityPublicKey.getEncoded();
        los.writeVariableLengthByteArray(servicePublicKeyBytes);
        los.writeVariableLengthByteArray(signature);
        los.writeVariableLengthByteArray(mac);
        los.flush();
    }
}
