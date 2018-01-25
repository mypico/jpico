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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.ISigmaVerifier.Client.ClientAuthorisation;
import org.mypico.jpico.crypto.messages.EncPicoAuthMessage;
import org.mypico.jpico.crypto.messages.EncServiceAuthMessage;
import org.mypico.jpico.crypto.messages.EncStatusMessage;
import org.mypico.jpico.crypto.messages.PicoAuthMessage;
import org.mypico.jpico.crypto.messages.ServiceAuthMessage;
import org.mypico.jpico.crypto.messages.StartMessage;
import org.mypico.jpico.crypto.messages.StatusMessage;
import org.mypico.jpico.crypto.messages.EncryptedMessage.FieldDeserializationException;

/**
 * Performs the SIGMA-I authentication protocol for the verifier (Service).
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class NewSigmaVerifier implements ISigmaVerifier {

    private static enum State {
        INITIAL("before authentication"),
        KEYGENERATED("Shared key generated"),
        STARTED("after authentication was started, but not completed"),
        AUTHENTICATED("after authentication was successful"),
        FAIL("after an error occurred");

        public final String when;

        private State(String when) {
            this.when = when;
        }
    }

    private State state = State.INITIAL;

    // Variables with names prefixed with 'p' are for values related to the prover and those
    // prefixed with 'v' are for values related to the verifier.

    // Initial variables:
    @SuppressWarnings("unused") // May be used later
    private final byte vVersion;
    private final KeyPair vIdKeyPair;
    private final KeyPair vEphemKeyPair;
    private final Nonce vNonce;
    private final int vSessionId;
    private final boolean vContinue;
    private final ISigmaVerifier.Client client;
    private final KeyAgreement ka;

    // Intermediate variables
    private PublicKey pEphemPubKey;
    private SecretKey pMacKey;
    private SecretKey pEncKey;
    private SecretKey vMacKey;
    private SecretKey vEncKey;

    // Output variables:
    private PublicKey pIdPubKey; // getProverIdPubKey
    private SecretKey sharedKey; // getSharedKey
    private byte[] pExtraData; // getReceivedExtraData
    private byte[] vExtraData; // getSentExtraData
    private boolean isContinuing = false; // isContinuing

    /**
     * Constructor.
     *
     * @param verifierVersion   The version of the protocol.
     * @param verifierIdKeyPair The service's long term identity key pair.
     * @param sessionId         The session id.
     * @param client            The Sigma Verifier for the service.
     * @param cont              true if continous authentication is desired, false o/w.
     */
    public NewSigmaVerifier(
        byte verifierVersion,
        KeyPair verifierIdKeyPair,
        int sessionId,
        ISigmaVerifier.Client client,
        boolean cont) {
        this.vVersion = verifierVersion;
        this.vIdKeyPair = checkNotNull(verifierIdKeyPair, "verifierIdKeyPair cannot be null");
        this.vSessionId = sessionId;
        this.vContinue = cont;
        this.client = checkNotNull(client, "client cannot be null");
        ka = CryptoFactory.INSTANCE.ecKeyAgreement();
        // Generate ephemeral verifier key pair and nonce
        vEphemKeyPair = CryptoFactory.INSTANCE.ecKpg().generateKeyPair();
        vNonce = Nonce.getRandomInstance();
    }

    @Override
    public synchronized EncServiceAuthMessage start(StartMessage msg) throws ProtocolViolationException {
        if (state == State.INITIAL) {
            // Retrieve and check items from the unencrypted Start Message:
            final Nonce pNonce;
            try {
                pNonce = checkNotNull(
                    msg.getPicoNonce(),
                    "pico nonce missing");
                pEphemPubKey = checkNotNull(
                    msg.getPicoEphemeralPublicKey(),
                    "pico ephemeral public key missing");
            } catch (NullPointerException e) {
                throw new ProtocolViolationException(e);
            }

            // Using the prover's ephemeral public key and the verifier's private ephemeral key, do
            // the Diffie-Hellman key agreement (ECDH). This generates a shared secret which is
            // used as a seed for the key derivarion procedure.
            try {
                ka.init(vEphemKeyPair.getPrivate());
            } catch (InvalidKeyException e) {
                // Re-thrown unchecked because this signals incompatibility between the chosen key
                // pair generation and key agreement algorithms.
                throw new CryptoRuntimeException(e);
            }
            try {
                ka.doPhase(pEphemPubKey, true);
            } catch (InvalidKeyException e) {
                throw new ProtocolViolationException(
                    "prover supplied invalid ephemeral public key", e);
            } catch (IllegalStateException e) {
                // Re-thrown unchecked because this block should be unreachable. The key agreement
                // is initialised above.
                throw new RuntimeException(e);
            }
            final byte[] ecdhSharedSecret = ka.generateSecret();
            // Carry out the key derivation procedure using the shared secret created above and the
            // two nonces. See the key deriver classes for more information on the key derivation
            // procedure.

            //There is a noticable second pause between the line above and the print statement on the first line of the method below

            KeyDeriver kd = SigmaKeyDeriver.getInstance(ecdhSharedSecret, pNonce, vNonce);
            pMacKey = kd.getNextKey("Hmac-SHA256", 256);
            pEncKey = kd.getNextKey("AES", 128);
            vMacKey = kd.getNextKey("Hmac-SHA256", 256);
            vEncKey = kd.getNextKey("AES", 128);
            sharedKey = kd.getNextKey("AES", 128);
            kd.destroy();

            state = State.KEYGENERATED;

            // Create and encrypt a Verifier Auth Message, returning it to the prover. The verifier
            // authenticates to the prover first (in the "I" variant of SIGMA) to protect the
            // prover's long term identity.
            final ServiceAuthMessage serviceAuthMessage;
            try {
                serviceAuthMessage = ServiceAuthMessage.getInstance(
                    vSessionId,
                    vEphemKeyPair.getPublic(),
                    vNonce,
                    pNonce,
                    vIdKeyPair,
                    vMacKey);
            } catch (InvalidKeyException e) {
                // Re-thrown unchecked because this signals that the signature algorithm has been
                // unable to process the supplied data to sign. This is considered an unrecoverable
                // error, probably resulting from incompatibility between the chosen crypto
                // algorithms.
                throw new CryptoRuntimeException(
                    "unable to create verifier auth message signature", e);
            } catch (SignatureException e) {
                // Re-thrown unchecked because this signals incompatibility between the key
                // generation algorithm used by the key deriver and the algorithm used to produce
                // the MAC, or incompatibility between the key pair generation algorhtm used for
                // the prover's long-term identity and the chosen signature algorithm.
                throw new CryptoRuntimeException(
                    "invalid verifier MAC key returned by key deriver", e);
            }
            state = State.STARTED;
            try {
                return serviceAuthMessage.encrypt(vEncKey);
            } catch (InvalidKeyException e) {
                // Re-thrown unchecked because this signals incompatibility between the chosen
                // symmetric key generation algorithm of the key deriver and the message cipher
                // scheme
                throw new CryptoRuntimeException(e);
            }
        } else {
            throw new IllegalStateException("invalid operation " + state.when);
        }
    }

    /**
     * @throws IOException if an IOException occurs while notifying the verifier's client of a
     *                     successful authentication (see {@link ISigmaVerifier.Client#onAuthenticate(PublicKey, byte[])}).
     */
    @Override
    public synchronized EncStatusMessage authenticate(EncPicoAuthMessage msg)
        throws ProtocolViolationException, IOException {
        if (state == State.STARTED) {
            // DECRYPT PROVER AUTH MESSAGE:
            // Decrypt the Prover Auth Message using the "prover encryption" derived key.
            final PicoAuthMessage proverAuthMessage;
            try {
                proverAuthMessage = msg.decrypt(pEncKey);
            } catch (InvalidKeyException e) {
                // Re-thrown unchecked because this signals incompatibility between the chosen
                // symmetric key generation algorithm of the key deriver and the message cipher
                // scheme
                throw new CryptoRuntimeException(e);
            } catch (InvalidAlgorithmParameterException e) {
                state = State.FAIL;
                throw new ProtocolViolationException("prover supplied invalid IV", e);
            } catch (IllegalBlockSizeException e) {
                state = State.FAIL;
                throw new ProtocolViolationException(
                    "prover supplied invalid encrypted data", e);
            } catch (BadPaddingException e) {
                state = State.FAIL;
                throw new ProtocolViolationException(
                    "prover supplied invalid encrypted data", e);
            } catch (FieldDeserializationException e) {
                state = State.FAIL;
                throw new ProtocolViolationException(
                    "prover supplied invalid encrypted data", e);
            }


            // PROVER AUTHENTICATION:
            // Having decrypted the Prover Auth Message, the verifier is now in a position to 
            // validate the prover's authentication. Two checks are carried out:
            // 1. Verify the signature in the message using the presented long-term identity public
            //    key. This checks the prover possesses the corresponding private key. The data
            //    signed includes the verifier nonce sent in the Verifier Auth Message.
            // 2. Check the MAC in the message. The message must include a keyed HMAC of the 
            //    prover's long-term identity public key. The key for this HMAC is derived from
            //    the ECDH shared secret, making it unforgeble for a MITM attempting an identity
            //    misbinding attack.

            // accept is initially true, but each of the three checks may set it to false, causing
            // the prover's authentication to be rejected (see RETURN STATUS MESSAGE section
            // below). As an optimisation, the second and third checks are only carried out if the
            // previous ones did not already set accept to false;
            pIdPubKey = proverAuthMessage.getPicoAccountIdentityPublicKey();
            boolean accept = true;

            assert (pIdPubKey != null);

            // 1. Verify the signature in the message using the long-term identity public key.
            if (accept) {
                final Signature sig = CryptoFactory.INSTANCE.sha256Ecdsa();
                try {
                    sig.initVerify(pIdPubKey);
                    sig.update(PicoAuthMessage.getBytesToSign(vNonce, vSessionId, pEphemPubKey));

                    // Set accept here
                    accept = sig.verify(proverAuthMessage.getSignature());

                } catch (InvalidKeyException e) {
                    // The public key presented by the prover was not of the correct type to have
                    // created the signature.
                    state = State.FAIL;
                    throw new ProtocolViolationException(
                        "prover supplied invalid identity public key", e);
                } catch (SignatureException e) {
                    // Verification of the signature was not possible. This is more serious than the
                    // signature being invalid, i.e. not corresponding to the presented public key.
                    state = State.FAIL;
                    throw new ProtocolViolationException(
                        "unable to verify signature presented by prover", e);
                }
            }

            // 2. Check the MAC in the message:
            if (accept) {
                final Mac mac = CryptoFactory.INSTANCE.sha256Hmac();
                try {
                    mac.init(pMacKey);
                } catch (InvalidKeyException e) {
                    // Re-thrown unchecked because this signals incompatibility between the key
                    // generation algorithm used by the key deriver and the algorithm used to produce
                    // the MAC.
                    throw new CryptoRuntimeException(
                        "invalid verifier MAC key returned by key deriver", e);
                }
                final byte[] vExpectedMac = mac.doFinal(pIdPubKey.getEncoded());

                // Set accept here
                accept = Arrays.equals(vExpectedMac, proverAuthMessage.getMac());
            }


            // RETURN STATUS MESSAGE:
            final StatusMessage statusMessage;
            if (accept) {
                // Prover's authentication was successful, but the client has the opportunity to
                // accept or reject the authentication based on the prover's identity and the
                // received extra data.
                // Note: pExtraData not accessible (via getReceivedExtraData) until state is set
                //       to State.AUTHENTICATED
                pExtraData = proverAuthMessage.getExtraData();
                final ClientAuthorisation auth = client.onAuthenticate(pIdPubKey, pExtraData);

                if (auth.authorised()) {
                    // The client has accepted the authentication
                    state = State.AUTHENTICATED;

                    // Response
                    vExtraData = auth.extraData();
                    if (vContinue) {
                        System.out.println("Continuous authentication");
                        isContinuing = true;
                        statusMessage = StatusMessage.getContinueInstance(vSessionId, vExtraData);
                    } else {
                        statusMessage = StatusMessage.getDoneInstance(vSessionId, vExtraData);
                    }
                } else {
                    // Client has rejected the authentication
                    state = State.FAIL;
                    statusMessage = StatusMessage.getRejectInstance(vSessionId);
                }
            } else {
                // Prover's authentication was invalid, reject.
                state = State.FAIL;
                statusMessage = StatusMessage.getRejectInstance(vSessionId);
            }
            // Encrypt and return the status message
            try {
                return statusMessage.encrypt(vEncKey);
            } catch (InvalidKeyException e) {
                // Re-thrown unchecked because this signals incompatibility between the chosen
                // symmetric key generation algorithm of the key deriver and the message cipher
                // scheme
                throw new CryptoRuntimeException(e);
            }
        } else {
            throw new IllegalStateException("invalid operation " + state.when);
        }
    }

    /**
     * Get the Pico's long term identity public key.
     *
     * @return The Pico identity public key.
     */
    public synchronized PublicKey getProverIdPubKey() {
        if (state == State.AUTHENTICATED) {
            return pIdPubKey;
        } else {
            throw new IllegalStateException("invalid operation " + state.when);
        }
    }

    /**
     * Get the shared key, used to encrypt data during the protocol and generated from the ECDH
     * shared secrets and both the prover and verifier nonces.
     * <p>
     * Both the verifier and prover can generate this key, but an eavesdropper cannot.
     *
     * @return the shared key.
     */
    public synchronized SecretKey getSharedKey() {
        // TODO: Check the change in state isn't detrimental
        // Was previously only allowed if (state == State.AUTHENTICATED)
        if ((state == State.AUTHENTICATED) || (state == State.KEYGENERATED) || (state == State.STARTED)) {
            return sharedKey;
        } else {
            throw new IllegalStateException("invalid operation " + state.when);
        }
    }

    /**
     * Get any extra data sent from the prover to the verifier.
     *
     * @return any extra data sent by the prover.
     */
    public synchronized byte[] getReceivedExtraData() {
        if (state == State.AUTHENTICATED) {
            return pExtraData;
        } else {
            throw new IllegalStateException("invalid operation " + state.when);
        }
    }

    /**
     * True if the prover has been authenticated and the process is now continuously authenticating.
     *
     * @return true if in the continuously authenticating state, false o/w.
     */
    public synchronized boolean isContinuing() {
        if (state == State.AUTHENTICATED) {
            return isContinuing;
        } else {
            throw new IllegalStateException("invalid operation " + state.when);
        }
    }
}
