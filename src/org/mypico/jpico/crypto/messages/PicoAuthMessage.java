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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
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
 * The third message of the SIGMA-I protocol, which is sent from the Pico to the service when the
 * Pico wants authenticate to the service using an existing account, or to create a new account.
 * <p>
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see org.mypico.jpico.crypto.messages.EncPicoAuthMessage
 */
public final class PicoAuthMessage extends UnencryptedMessage<EncPicoAuthMessage> {

    private final PublicKey picoAccountIdentityPublicKey;
    private final byte[] signature;
    private final byte[] mac;
    private final byte[] extraData;

    /**
     * Constructor.
     *
     * @param sessionId                    The session id.
     * @param picoAccountIdentityPublicKey The long term identity public key of the prover (Pico).
     * @param signature                    The signature of the data.
     * @param mac                          The mac of the data.
     * @param extraData                    Any extra data, sent encrypted to the verifier.
     */
    PicoAuthMessage(
        final int sessionId,
        final PublicKey picoAccountIdentityPublicKey,
        final byte[] signature,
        final byte[] mac,
        final byte[] extraData) {
        super(sessionId);
        this.picoAccountIdentityPublicKey = picoAccountIdentityPublicKey;
        this.signature = signature;
        this.mac = mac;
        if (extraData == null) {
            this.extraData = new byte[0];
        } else {
            this.extraData = extraData;
        }
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
     * Get the long term public identity key of the prover (Pico).
     *
     * @return the Pico's identity public key.
     */
    public PublicKey getPicoAccountIdentityPublicKey() {
        return picoAccountIdentityPublicKey;
    }

    /**
     * Get the signature used to prove the message was sent by the Pico.
     *
     * @return the message signature.
     */
    public byte[] getSignature() {
        return signature;
    }

    /**
     * Get the message authentication code that demoonstrates the integrity of the message.
     *
     * @return the message MAC.
     */
    public byte[] getMac() {
        return mac;
    }

    /**
     * Get the extra data sent encrypted with the message by the Pico.
     *
     * @return the extra data sent by the Pico.
     */
    public byte[] getExtraData() {
        return extraData;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof PicoAuthMessage) {
            PicoAuthMessage other = (PicoAuthMessage) obj;
            return (sessionId == other.sessionId)
                && Arrays.equals(picoAccountIdentityPublicKey.getEncoded(),
                other.picoAccountIdentityPublicKey.getEncoded())
                && Arrays.equals(signature, other.signature)
                && Arrays.equals(mac, other.mac)
                && Arrays.equals(extraData, other.extraData);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sessionId, picoAccountIdentityPublicKey, signature,
            mac, extraData);
    }

    /**
     * Obviously not the entire message can be signed (e.g. the signature isn't signed). This
     * method takes the data elements, turns them into a data stream and then signs the resulting
     * stream of data.
     *
     * @param serviceNonce           The service's nonce.
     * @param sessionId              The session id.
     * @param picoEphemeralPublicKey The ephemeral public key of the prover (Pico).
     * @return the signed data.
     */
    public static byte[] getBytesToSign(
        final Nonce serviceNonce,
        final int sessionId,
        final PublicKey picoEphemeralPublicKey) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.write(serviceNonce.getValue());
            dos.writeInt(sessionId);
            dos.write(picoEphemeralPublicKey.getEncoded());
        } catch (IOException e) {
            // Exception is re-thrown because a ByteArrayOutputStream specifically cannot raise
            // IOExceptions.
            throw new RuntimeException(e);
        }
        return baos.toByteArray();
    }

    /**
     * Perform verification check on message (specifically, check the signature and MAC that form
     * part of the message.
     *
     * @param serviceNonce           The nonce contained in the message.
     * @param picoMacKey             The symmetric key used to generate the MAC.
     * @param picoEphemeralPublicKey The assymetric ephemeral key being used by the prover for this
     *                               session.
     * @return true if the verification succeeds, false o/w.
     * @throws GeneralSecurityException if an error occurs in the verification process (e.g. the
     *                                  key is not valid).
     * @deprecated removed to simplify message class implementation. Callers should implement
     * verification checks themselves.
     */
    @Deprecated
    public boolean verify(final Nonce serviceNonce, final SecretKey picoMacKey,
                          final PublicKey picoEphemeralPublicKey)
        throws GeneralSecurityException {
        checkNotNull(serviceNonce);
        checkNotNull(picoMacKey);
        checkNotNull(picoEphemeralPublicKey);

        // Check that the public key signature is correct
        final Signature signer = CryptoFactory.INSTANCE.sha256Ecdsa();
        signer.initVerify(picoAccountIdentityPublicKey);
        signer.update(getBytesToSign(serviceNonce, sessionId, picoEphemeralPublicKey));
        if (!signer.verify(this.signature)) {
            return false;
        }

        // Check that the symmetric key MAC is correct.
        final Mac macer = CryptoFactory.INSTANCE.sha256Hmac();
        macer.init(picoMacKey);
        if (!Arrays.equals(
            macer.doFinal(picoAccountIdentityPublicKey.getEncoded()), this.mac)) {
            return false;
        }

        // All the checks have passed.
        return true;
    }

    /**
     * Creates a PicoAuthMessage, using the provided keys to link the ephemeral keys to the Pico's
     * long term account identity key.
     *
     * @param sessionId              Identifies the session to the service.
     * @param serviceNonce           The nonce sent as part of the message.
     * @param picoEphemeralPublicKey The prover's ephemeral public key for the session.
     * @param picoIdKeyPair          The prover's long-term identity key pair.
     * @param picoMacKey             is one of the derived keys from the DH Key agreement.
     * @param extraData              additional message contents to send from the Pico to the service. This
     *                               data will be sent encrypted.
     * @return The resulting {@code PicoAuthMessage} instance created.
     * @throws InvalidKeyException if one of the supplied keys is not valid.
     * @throws SignatureException  if the signature cannot be created with the supplied arguments.
     */
    public static PicoAuthMessage getInstance(
        final int sessionId,
        final Nonce serviceNonce,
        final PublicKey picoEphemeralPublicKey,
        final KeyPair picoIdKeyPair,
        final SecretKey picoMacKey,
        final byte[] extraData) throws InvalidKeyException, SignatureException {
        // Get the bytes to be signed:
        // serviceNonce||sessionId||picoEphemeralPublicKey
        byte[] bytesToSign = getBytesToSign(serviceNonce, sessionId, picoEphemeralPublicKey);

        // Sign using the Pico's long-term private key:
        Signature signer = CryptoFactory.INSTANCE.sha256Ecdsa();
        signer.initSign(picoIdKeyPair.getPrivate());
        signer.update(bytesToSign);
        byte[] signature = signer.sign();

        // Make the MAC of the Pico's long-term public key, using the derived Pico MAC key:
        Mac macer = CryptoFactory.INSTANCE.sha256Hmac();
        macer.init(picoMacKey);
        byte[] mac = macer.doFinal(picoIdKeyPair.getPublic().getEncoded());

        return new PicoAuthMessage(
            sessionId, picoIdKeyPair.getPublic(), signature, mac, extraData);
    }

    @Override
    protected EncPicoAuthMessage createEncryptedMessage(
        final byte[] encryptedData, final byte[] iv) {
        return new EncPicoAuthMessage(sessionId, encryptedData, iv);
    }

    @Override
    protected void writeDataToEncrypt(LengthPrependedDataOutputStream los) throws IOException {
        byte[] picoPublicKeyBytes = picoAccountIdentityPublicKey.getEncoded();
        los.writeVariableLengthByteArray(picoPublicKeyBytes);
        los.writeVariableLengthByteArray(signature);
        los.writeVariableLengthByteArray(mac);
        los.writeVariableLengthByteArray(extraData);
        los.flush();
    }
}
