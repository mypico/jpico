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
import javax.security.auth.Destroyable;

/**
 * A KeyDeriver is used to derive one or more cryptographic keys from a shared secret established by
 * a a public-key-based key establishment scheme, such as Diffie-Hellman key exchange.
 * <p>
 * <p>
 * This class was implemented according to the NIST document, SP 800-56C, Recommendation for Key
 * Derivation through Extraction-then-Expansion (<a
 * href="http://csrc.nist.gov/publications/nistpubs/800-56C/SP-800-56C.pdf"
 * >http://csrc.nist.gov/publications/nistpubs/800-56C/SP-800-56C.pdf</a>‎). Specifically, a
 * KeyDeriver adheres to the general scheme set out in SP 800-56C, in which there are two steps: a
 * randomness extraction step, followed by a key expansion step. The result of the randomness
 * extraction step is K<sub>DK</sub>, the key derivation key, which is then the key for the hash
 * function used during the key expansion step. Concrete implementations of each of these steps are
 * left for subclasses to implement.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public abstract class KeyDeriver implements Destroyable {

    protected final int blockSizeInBytes;
    protected final Mac keyExpansionMac;
    protected final byte[] currentBlock;

    private boolean isInitialised = false;
    private int numCurrentBlockBytesUsed;

    /**
     * @param blockSizeInBytes size of each block produced by subclasses' implementation of
     *                         {@link #nextBlock() nextBlock}. This value is used to allocate {@link #currentBlock
     *                         currentBlock}.
     * @param keyExpansionMac  Mac instance used for key expansion.
     */
    protected KeyDeriver(final int blockSizeInBytes, final Mac keyExpansionMac) {
        this.blockSizeInBytes = blockSizeInBytes;
        this.keyExpansionMac = keyExpansionMac;
        this.currentBlock = new byte[blockSizeInBytes];

        // This will cause nextBlock to be called the first time getNextKey is
        // called even though no bytes of the current block have been "used".
        this.numCurrentBlockBytesUsed = blockSizeInBytes;
    }

    /**
     * Initialises the {@link #keyExpansionMac keyExpansionMac} with the result of
     * {@link #extractRandomness() extractRandomness}.
     * <p>
     * <p>
     * This method should be called by the constructors of subclasses once the prerequisite values
     * for the randomness extraction step have been initialised.
     *
     * @throws IllegalStateException if the deriver has already been initialised.
     */
    protected final void initialise() {
        if (isInitialised) {
            throw new IllegalStateException("Key deriver is already initialised.");
        }

        try {
            keyExpansionMac.init(extractRandomness());
        } catch (InvalidKeyException e) {
            // This exception is caught and re-thrown because extractRandomness should not ever
            // return an invalid key and it is considered a fatal programmer error from which the
            // program cannot recover. If the extractRandomness method cannot return a valid key it
            // should throw an exception.
            throw new RuntimeException("randomness extraction step returned an invalid key", e);
        }

        isInitialised = true;
    }

    /**
     * Reports whether or not the key deriver is "initialised" and is ready to produce new keys.
     * <p>
     * <p>
     * A key deriver is initialised once the {@link #initialise() initialise} method has been called
     * by a subclass.
     *
     * @return true if the key deriver is initialised, and false otherwise.
     */
    public final boolean isInitialised() {
        return isInitialised;
    }

    /**
     * Get a new Key for a given algorithm, with a specified length in bits.
     * <p>
     * <p>
     * This method will first use all currently available derived keying material and will only then
     * call {@link #nextBlock() nextBlock} if further bits are required.
     *
     * @param algorithm the name of the algorithm the key will be used for.
     * @param length    the desired length of the key in bits, which is assumed to be a multiple of 8.
     *                  Note: You may give an invalid algorithm/length combination and this method will not
     *                  throw an exception.
     * @return the new Key instance.
     * @throws IllegalStateException if the key deriver has not been initialised or has been
     *                               destroyed.
     */
    public SecretKey getNextKey(final String algorithm, final int length) {
        // Ensure deriver is initialised
        if (!isInitialised) {
            throw new IllegalStateException("key deriver has not been initialised");
        }

        // Ensure deriver is not destroyed
        if (isDestroyed) {
            throw new IllegalStateException("key deriver has been destroyed");
        }

        final int numKeyBytes = length / 8;
        byte[] keyBytes = new byte[numKeyBytes];

        try {
            // Fill keyBytes
            int numKeyBytesFilled = 0;
            while (numKeyBytesFilled < numKeyBytes) {
                // Maybe do more key expansion
                assert (numCurrentBlockBytesUsed <= blockSizeInBytes);
                if (numCurrentBlockBytesUsed == blockSizeInBytes) {
                    // Derive the next block of keying material
                    nextBlock();
                    numCurrentBlockBytesUsed = 0;
                }

                // Determine how bytes to copy
                final int remaining = numKeyBytes - numKeyBytesFilled;
                final int available =
                    blockSizeInBytes - numCurrentBlockBytesUsed;
                final int toCopy;
                if (remaining >= available) {
                    toCopy = available;
                } else {
                    toCopy = remaining;
                }

                // Copy the bytes from currentBlock to keyBytes
                System.arraycopy(
                    currentBlock, // source array
                    numCurrentBlockBytesUsed, // source array offset
                    keyBytes, // destination array
                    numKeyBytesFilled, // destination array offset
                    toCopy // length to copy
                );

                // Update variables
                numCurrentBlockBytesUsed += toCopy;
                numKeyBytesFilled += toCopy;
            }

            // Construct and return the key
            return new SecretKeySpec(keyBytes, algorithm);
        } finally {
            // Clean up working byte array
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Derive K<sub>DK</sub>, the key derivation key, from the initial shared secret material.
     *
     * @return K<sub>DK</sub>, the key derivation key.
     */
    protected abstract Key extractRandomness();

    /**
     * Carry out another round of key expansion to derive more keying material from the key
     * derivation key, writing the resulting bytes to {@link #currentBlock currentBlock}.
     */
    protected abstract void nextBlock();

    // implements Destroyable

    protected boolean isDestroyed = false;

    @Override
    public void destroy() {
        Arrays.fill(currentBlock, (byte) 0);
        numCurrentBlockBytesUsed = 0;
        // TODO clear keyExpansionMac
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }
}
