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


package org.mypico.jpico.visualcode;

import com.google.gson.annotations.SerializedName;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.mypico.jpico.Preconditions;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.data.pairing.KeyPairing;

/**
 * VisualCode containing details to pair with a service.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public class KeyPairingVisualCode extends KeyVisualCode implements SignedVisualCode {

    public static String TYPE = "KP";

    /**
     * Returns a new signed <code>KeyPairingVisualCode</code> instance with terminal fields set.
     *
     * @param serviceAddress     The address of the service.
     * @param terminalAddress    The address of the terminal to interact with.
     * @param terminalCommitment The commitment of the terminal to interact with.
     * @param serviceName        The name of the service to authenticate to.
     * @param serviceKeyPair     The keypair of the service to authenticate to.
     * @return The generated <code>KeyPairingVisualCode</code> instance.
     * @throws InvalidKeyException if an ECDSA signature cannot be created with the supplied key
     *                             pair.
     */
    public static KeyPairingVisualCode getSignedInstance(
        final URI serviceAddress,
        final URI terminalAddress,
        final byte[] terminalCommitment,
        final String serviceName,
        final KeyPair serviceKeyPair) throws InvalidKeyException {
        return getSignedInstance(serviceAddress, terminalAddress, terminalCommitment, serviceName, serviceKeyPair, null);
    }

    /**
     * Returns a new signed <code>KeyPairingVisualCode</code> instance with terminal fields set.
     *
     * @param serviceAddress     The address of the service.
     * @param terminalAddress    The address of the terminal to interact with.
     * @param terminalCommitment The commitment of the terminal to interact with.
     * @param serviceName        The name of the service to authenticate to.
     * @param serviceKeyPair     The keypair of the service to authenticate to.
     * @param extraData          The extra data to send.
     * @return The generated <code>KeyPairingVisualCode</code> instance.
     * @throws InvalidKeyException if an ECDSA signature cannot be created with the supplied key
     *                             pair.
     */
    public static KeyPairingVisualCode getSignedInstance(
        final URI serviceAddress,
        final URI terminalAddress,
        final byte[] terminalCommitment,
        final String serviceName,
        final KeyPair serviceKeyPair,
        final byte[] extraData) throws InvalidKeyException {
        final KeyPairingVisualCode code = new KeyPairingVisualCode();
        code.serviceAddress = Preconditions.checkNotNullOrEmpty(
            serviceAddress, "serviceAddress cannot be null or empty");
        code.serviceName = Preconditions.checkNotNullOrEmpty(
            serviceName, "serviceName cannot be null or empty");
        code.extraData = extraData;
        // Add terminal details
        code.terminal = TerminalDetails.getInstance(terminalAddress, terminalCommitment);

        // Add key and sign
        checkNotNull(serviceKeyPair, "serviceKeyPair cannot be null");
        code.servicePublicKey = serviceKeyPair.getPublic();
        try {
            code.sign(serviceKeyPair.getPrivate());
        } catch (SignatureException e) {
            // Re-thrown because this exception indicates that the signature cannot be created
            // using the bytes returned by getBytesToSign, which should only occur as a result of
            // a program error.
            throw new RuntimeException("unable to create signature", e);
        }
        return code;
    }

    /**
     * Returns a new signed <code>KeyPairingVisualCode</code> instance without terminal fields set.
     *
     * @param serviceAddress The address of the service to authenticate to.
     * @param serviceName    The name of the service to authenticate to.
     * @param serviceKeyPair The keypir of the service.
     * @return The signed <code>KeyPairingVisualCode</code> generated.
     * @throws InvalidKeyException if an ECDSA signature cannot be created with the supplied key
     *                             pair.
     */
    public static KeyPairingVisualCode getSignedInstanceNoTerminal(
        final URI serviceAddress,
        final String serviceName,
        final KeyPair serviceKeyPair) throws InvalidKeyException {
        return getSignedInstanceNoTerminal(serviceAddress, serviceName, serviceKeyPair, null);
    }

    /**
     * Returns a new signed <code>KeyPairingVisualCode</code> instance without terminal fields set.
     *
     * @param serviceAddress The address of the service to authenticate to.
     * @param serviceName    The name of the service to authenticate to.
     * @param serviceKeyPair The keypir of the service.
     * @param extraData      The extra data to send.
     * @return The signed <code>KeyPairingVisualCode</code> generated.
     * @throws InvalidKeyException if an ECDSA signature cannot be created with the supplied key
     *                             pair.
     */
    public static KeyPairingVisualCode getSignedInstanceNoTerminal(
        final URI serviceAddress,
        final String serviceName,
        final KeyPair serviceKeyPair,
        final byte[] extraData) throws InvalidKeyException {
        final KeyPairingVisualCode code = new KeyPairingVisualCode();
        code.serviceAddress = Preconditions.checkNotNullOrEmpty(
            serviceAddress, "serviceAddress cannot be null or empty");
        code.serviceName = Preconditions.checkNotNullOrEmpty(
            serviceName, "serviceName cannot be null or empty");
        // Add empty terminal details
        code.terminal = TerminalDetails.getEmptyInstance();
        code.extraData = extraData;

        // Add key and sign
        checkNotNull(serviceKeyPair, "serviceKeyPair cannot be null");
        code.servicePublicKey = serviceKeyPair.getPublic();
        try {
            code.sign(serviceKeyPair.getPrivate());
        } catch (SignatureException e) {
            // Re-thrown because this exception indicates that the signature cannot be created
            // using the bytes returned by getBytesToSign, which should only occur as a result of
            // a program error.
            throw new RuntimeException("unable to create signature", e);
        }
        return code;
    }

    @SerializedName("sn")
    private String serviceName;
    @SerializedName("spk")
    private PublicKey servicePublicKey;
    @SerializedName("sig")
    private byte[] signature;
    @SerializedName("ed")
    private byte[] extraData;

    private transient byte[] serviceCommitment;

    // no-args constructor for Gson
    protected KeyPairingVisualCode() {
        super(TYPE);
    }

    @Override
    public boolean isValid() {
        return super.isValid() &&
            serviceName != null &&
            signature != null &&
            validateSignature();
        // note: extra data is not checked, because it's optional (I think)
    }

    /**
     * Validate the signature field. This does not check the signature, only that the contents of
     * the field forms something that looks like a signature.
     *
     * @return {@code true} if the signature field has the correct format, {@code false} otherwise.
     */
    private boolean validateSignature() {
        /* The signature field is ASN.1 DER encoded (see wki.pe/Abstract_Syntax_Notation_One)
		 * with the following format:
		 * 
		 * EcdsaSignature ::= SEQUENCE {
		 *     r INTEGER,
		 *     s INTEGER
		 * }
		 * 
		 * As far as the raw bytes are concerned, we have:
		 *    0x30     SEQUENCE type tag
		 *    0xLL     length of following value -- thus length of sig is LL+2
		 *      0x02   INTEGER type tag
		 *      0xMM   length of following value
		 *      ....   MM bytes of data
		 *      0x02   INTEGER type tag
		 *      0xNN   length of following value
		 *      ....   NN bytes of data
		 */
        return signature.length > 6 && // lower bound, there should be three elements
            // validate the SEQUENCE tag
            signature[0] == 0x30 &&
            signature[1] == (signature.length - 2) &&
            // validate the first INTEGER tag
            signature[2] == 0x02 &&
            (4 + (int) signature[3]) < (signature.length - 1) &&
            // validate that there is another INTEGER tag after it
            signature[4 + signature[3]] == 0x02 &&
            // and check the lengths add up correctly
            (6 + (int) signature[3] + (int) signature[5 + signature[3]]) == signature.length;
    }

    /**
     * Get the name of the service identified by this visual code.
     *
     * @return the name of the service identified by this visual code.
     */
    public String getServiceName() {
        return serviceName;
    }

    /**
     * Get the service commitment from the code.
     *
     * @return the service commitment.
     */
    public byte[] getServiceCommitment() {
        if (serviceCommitment == null) {
            serviceCommitment = KeyPairing.commitServicePublicKey(servicePublicKey);
        }
        return serviceCommitment;
    }

    /**
     * @return the public key of the service identified by this visual code.
     */
    public PublicKey getServicePublicKey() {
        return servicePublicKey;
    }

    @Override
    public byte[] getSignature() {
        return signature;
    }

    /**
     * Get the extra data from the code.
     *
     * @return the extra data.
     */
    public byte[] getExtraData() {
        return extraData;
    }

    /**
     * Get the bytes to be signed for this <code>KeyPairVisualCode</code>. The fields of the visual
     * code are concatenated in the following order and format:
     * <p>
     * <p>
     * <code>serviceName</code>||<code>serviceAddress</code>
     * <p>
     * <p>
     * Where:
     * <p>
     * <ul>
     * <li><code>serviceName</code> is the service's name (see {@link #getServiceName()}), UTF-8
     * encoded.
     * <li><code>serviceAddress</code> is the service's address (see {@link #getServiceAddress()}),
     * UTF-8 encoded.
     * </ul>
     * <p>
     * <p>
     * The signature is created using the private key corresponding to the public key included in
     * the visual code (see {@link #getServicePublicKey()}).
     *
     * @return byte array containing bytes to be signed.
     */
    public byte[] getBytesToSign() {
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        final Charset utf8 = Charset.forName("UTF-8");
        try {
            os.write(serviceName.getBytes(utf8));
            os.write(serviceAddress.toString().getBytes(utf8));
        } catch (IOException e) {
            throw new IllegalStateException(
                "ByteArrayOutputStream should never throw an IOException here", e);
        }
        return os.toByteArray();
    }

    /**
     * Sign the code.
     *
     * @param servicePrivateKey The service's long term identity private key to sign the code with.
     * @throws InvalidKeyException thrown in case the key is invalid.
     * @throws SignatureException  thrown in case the signing fails.
     */
    private void sign(final PrivateKey servicePrivateKey)
        throws InvalidKeyException, SignatureException {
        // Verify the method's preconditions
        checkNotNull(servicePrivateKey, "servicePrivateKey cannot be null");

        final Signature sig = CryptoFactory.INSTANCE.sha256Ecdsa();
        sig.initSign(servicePrivateKey);
        sig.update(getBytesToSign());
        signature = sig.sign();
    }

}
