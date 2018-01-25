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

import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.mypico.jpico.comms.org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Concrete KeyDeriver implementation used for the SIGMA protocol, based on the key derivation
 * protocol used in Internet Key Exchange (IKE), as specified in <a
 * href="http://tools.ietf.org/search/rfc4306#section-2.13">RFC 4306</a> and <a
 * href="http://csrc.nist.gov/publications/nistpubs/800-135-rev1/sp800-135-rev1.pdf">
 * NIST SP 800-135</a>.
 * <p>
 * <p>
 * In the randomness extraction step (see {@link #extractRandomness extractRandomNess}), the key
 * derivation key is derived by taking the SHA256 HMAC of the shared secret obtained using a prior
 * public-key-based key agreement procedure, where the key to the HMAC is
 * <code>N<sub>P</sub> || N<sub>S</sub></code> where <code>N<sub>P</sub></code> is the nonce sent by
 * the Pico and <code>N<sub>S</sub></code> is the nonce sent by the service.
 * <p>
 * <p>
 * In the key expansion step (see {@link #nextBlock() nextBlock}), each block of key material is
 * derived using a SHA256 HMAC. The key to the HMAC is the key deriving key, and the message for
 * block k, <code>B<sub>k</sub></code>, is:
 * <code>B<sub>k-1</sub> || k || N<sub>P</sub> || N<sub>S</sub></code>, except for the first block
 * (see {@link #START_BLOCK_NUMBER}), where the previous block component is ommitted.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Chris Warrington &lt;cw471@cl.cam.ac.uk&gt;
 * @see KeyDeriver
 */
public class SigmaKeyDeriver extends KeyDeriver {

    private static final Logger LOGGER = LoggerFactory.getLogger(
        SigmaKeyDeriver.class.getSimpleName());

    @Deprecated
    /**
     * Container for the five dervied symmetric keys required for the Pico authentication protocol.
     *
     * @author Chris Warrington <cw471@cl.cam.ac.uk>
     * @deprecated Instead just reference the keys individually.
     *
     */
    static class DerivedKeys {
        public final SecretKey picoMacKey;
        public final SecretKey picoEncryptKey;
        public final SecretKey serviceMacKey;
        public final SecretKey serviceEncryptKey;
        public final SecretKey sharedKey;

        DerivedKeys(
            SecretKey picoMacKey,
            SecretKey picoEncryptKey,
            SecretKey serviceMacKey,
            SecretKey serviceEncryptKey,
            SecretKey sharedKey) {
            this.picoMacKey = picoMacKey;
            this.picoEncryptKey = picoEncryptKey;
            this.serviceMacKey = serviceMacKey;
            this.serviceEncryptKey = serviceEncryptKey;
            this.sharedKey = sharedKey;
        }
    }

    private static final String RAND_EXT_MAC_ALG = CryptoFactory.HMAC_SHA256;
    private static final String KEY_EXP_MAC_ALG = CryptoFactory.HMAC_SHA256;

    /**
     * Number of bytes produced during each round of key expansion.
     */
    public static final int BLOCK_SIZE_IN_BYTES = 32; // = 256 bits

    /**
     * Starting key expansion block number.
     */
    public static final int START_BLOCK_NUMBER = 1;

    /**
     * Maximum key expansion block number.
     */
    public static final int MAX_BLOCK_NUMBER = 255; // 0xff

    private final byte[] sharedSecret;
    private final byte[] nonces;
    private int currentBlockNumber = START_BLOCK_NUMBER;

    /**
     * Constructor.
     *
     * @param sharedSecret The shared secret generated from the ECDH exchange.
     * @param picoNonce    The Pico's nonce.
     * @param serviceNonce The service's nonce.s
     */
    private SigmaKeyDeriver(
        final byte[] sharedSecret, final Nonce picoNonce, final Nonce serviceNonce) {
        super(BLOCK_SIZE_IN_BYTES, CryptoFactory.INSTANCE.sha256Hmac());
        System.out.println("called superclass constructor, setting local fields");
        this.sharedSecret = sharedSecret;
        this.nonces = concatByteArrays(picoNonce.getValue(), serviceNonce.getValue());
        System.out.println("fields set");


        LOGGER.debug(
            "Initial shared secret ({} bytes): {}",
            sharedSecret.length,
            Base64.encodeBase64String(this.sharedSecret));
        LOGGER.debug(
            "Concatenated nonces ({} bytes): {}",
            nonces.length,
            Base64.encodeBase64String(nonces));
    }

    @Override
    protected Key extractRandomness() {
        byte[] keyBytes = null;
        try {
            // Initialise randomness extraction Mac
            Mac mac = CryptoFactory.INSTANCE.sha256Hmac();
            mac.init(new SecretKeySpec(nonces, RAND_EXT_MAC_ALG));
            // Make and return key deriving key
            keyBytes = mac.doFinal(sharedSecret);
            return new SecretKeySpec(keyBytes, KEY_EXP_MAC_ALG);
        } catch (InvalidKeyException e) {
            throw new CryptoRuntimeException(
                "Concatenated nonces invalid key for randomness " +
                    "extraction MAC algorithm (" + RAND_EXT_MAC_ALG + ")", e);
        } finally {
            // Clean up work byte arrays
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
            // TODO SecretKeySpec copies the byte array used to construct it,
            // so we need a way to destroy (zeroise) the inline SecretKeySpec
            // constructed from nonces and used to initialise mac.
        }
    }

    /**
     * @throws IllegalStateException if the current block number exceeds {@link #MAX_BLOCK_NUMBER}.
     * @see KeyDeriver#nextBlock()
     */
    @Override
    protected void nextBlock() {
        if (currentBlockNumber > MAX_BLOCK_NUMBER) {
            throw new IllegalStateException("");
        }

        byte[] newBlockMacMessage = null;
        byte[] newBlock = null;
        try {
            if (currentBlockNumber == START_BLOCK_NUMBER) {
                newBlockMacMessage = concatByteArrays(
                    nonces,
                    new byte[]{(byte) currentBlockNumber}
                );
            } else {
                newBlockMacMessage = concatByteArrays(
                    currentBlock,
                    nonces,
                    new byte[]{(byte) currentBlockNumber}
                );
            }
            currentBlockNumber += 1;
            newBlock = keyExpansionMac.doFinal(newBlockMacMessage);
            System.arraycopy(newBlock, 0, currentBlock, 0, BLOCK_SIZE_IN_BYTES);
        } finally {
            // Clean up work byte arrays
            if (newBlockMacMessage != null) {
                Arrays.fill(newBlockMacMessage, (byte) 0);
            }
            if (newBlockMacMessage != null) {
                Arrays.fill(newBlock, (byte) 0);
            }
        }
    }

    @Deprecated
    public DerivedKeys getAllKeys() {
        SecretKey picoMacKey = getNextKey("Hmac-SHA256", 256);
        SecretKey picoEncryptKey = getNextKey("AES", 128);
        SecretKey serviceMacKey = getNextKey("Hmac-SHA256", 256);
        SecretKey serviceEncryptKey = getNextKey("AES", 128);
        SecretKey sharedKey = getNextKey("AES", 128);

        LOGGER.debug(
            "Derived Pico MAC key (format={}): {}",
            picoMacKey.getFormat(),
            Base64.encodeBase64String(picoMacKey.getEncoded()));
        LOGGER.debug(
            "Derived Pico encrypt key (format={}): {}",
            picoEncryptKey.getFormat(),
            Base64.encodeBase64String(picoEncryptKey.getEncoded()));
        LOGGER.debug(
            "Derived Service MAC key (format={}): {}",
            serviceMacKey.getFormat(),
            Base64.encodeBase64String(serviceMacKey.getEncoded()));
        LOGGER.debug(
            "Derived Service encrypt key (format={}): {}",
            serviceEncryptKey.getFormat(),
            Base64.encodeBase64String(serviceEncryptKey.getEncoded()));
        LOGGER.debug(
            "Derived shared key (format={}): {}",
            sharedKey.getFormat(),
            Base64.encodeBase64String(sharedKey.getEncoded()));

        return new DerivedKeys(
            picoMacKey,
            picoEncryptKey,
            serviceMacKey,
            serviceEncryptKey,
            sharedKey);
    }

    /*
     * Concatenate a series of byte arrays into a newly allocated byte array.
     */
    private static byte[] concatByteArrays(final byte[]... arrays) {
        // Determine length for the new array
        int totalLength = 0;
        for (byte[] b : arrays) {
            totalLength += b.length;
        }

        // Allocate
        final byte[] newArray = new byte[totalLength];

        // Copy inputs into new output array
        int currentEnd = 0;
        for (byte[] b : arrays) {
            System.arraycopy(b, 0, newArray, currentEnd, b.length);
            currentEnd += b.length;
        }

        return newArray;
    }

    /**
     * Construct, initialise and return a new SigmaKeyDeriver instance.
     *
     * @param sharedSecret shared, secret, pre-key material obtained using a prior key agreement
     *                     procedure.
     * @param picoNonce    the nonce sent by the Pico.
     * @param serviceNonce the nonce sent by the service.
     * @return newly constructed and initialised (see {@link #initialise() initialise}),
     * SigmaKeyDeriver instance.
     */
    public static SigmaKeyDeriver getInstance(
        final byte[] sharedSecret, final Nonce picoNonce, final Nonce serviceNonce) {
        System.out.println("Constructing...");
        SigmaKeyDeriver d = new SigmaKeyDeriver(sharedSecret, picoNonce, serviceNonce);
        System.out.println("Done constructing");
        // Initialise the key deriver -- carries out the randomness extraction step and sets the
        // state to initialised.
        System.out.println("Extracting randomness");
        d.initialise();
        System.out.println("Done extracting randomness");
        return d;
    }

    // implements Destroyable

    @Override
    public void destroy() {
        super.destroy();
        Arrays.fill(sharedSecret, (byte) 0);
        Arrays.fill(nonces, (byte) 0);
        currentBlockNumber = 0;
    }
}
