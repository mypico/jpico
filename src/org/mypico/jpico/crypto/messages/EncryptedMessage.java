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

import com.google.common.base.Objects;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.util.LengthPrependedDataInputStream;

/**
 * Abstract base class for the encrypted forms of messages.
 * <p>
 * <p>All subclasses implement the <code>decrypt</code> method, which returns an instance of the
 * corresponding {@link UnencryptedMessage} subclass.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see UnencryptedMessage
 */
public abstract class EncryptedMessage<U extends UnencryptedMessage<?>>
    extends Message {

    public static class FieldDeserializationException extends Exception {

        private static final long serialVersionUID = -2251777007578448888L;

        public FieldDeserializationException() {
            super();
        }

        public FieldDeserializationException(String message, Throwable cause) {
            super(message, cause);
        }

        public FieldDeserializationException(String message) {
            super(message);
        }

        public FieldDeserializationException(Throwable cause) {
            super(cause);
        }

    }

    protected final int sessionId;
    protected final byte[] encryptedData;
    protected final byte[] iv;

    /**
     * Constructor.
     *
     * @param sessionId     The session id.
     * @param encryptedData The data to encrypt.
     * @param iv            The iv to use for encryption.
     */
    public EncryptedMessage(int sessionId, byte[] encryptedData, byte[] iv) {
        this.sessionId = sessionId;
        this.encryptedData = encryptedData;
        this.iv = iv;
    }

    /**
     * Get the session id.
     *
     * @return the session id.
     */
    public final int getSessionId() {
        return sessionId;
    }

    /**
     * Decrypt the message.
     *
     * @param key The decryption key.
     * @return The decrypted message object.
     * @throws InvalidKeyException                thrown if the decryption key is invalid.
     * @throws InvalidAlgorithmParameterException thrown if the parameters for the algorithm are
     *                                            invalid.
     * @throws IllegalBlockSizeException          thrown if the block sizes are incorrect.
     * @throws BadPaddingException                thown if the padding is invalid.
     * @throws FieldDeserializationException      thrown if an error occurs during deserialization.
     */
    public final U decrypt(SecretKey key)
        throws InvalidKeyException, InvalidAlgorithmParameterException,
        IllegalBlockSizeException, BadPaddingException, FieldDeserializationException {
        Cipher cipher = CryptoFactory.INSTANCE.aes256();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Initialise cipher with IV and encryption key
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        final byte[] decryptedData = cipher.doFinal(encryptedData);

        try {
            LengthPrependedDataInputStream dis = null;
            try {
                dis = new LengthPrependedDataInputStream(new ByteArrayInputStream(decryptedData));
                return createUnencryptedMessage(dis);
            } finally {
                if (dis != null) {
                    dis.close();
                }
            }
        } catch (IOException e) {
            // Re-thrown unchecked because ByteArrayInputStream should never raise any IOExceptions
            throw new RuntimeException(e);
        }
    }

    /**
     * Should be overriden to construct the unencrypted message.
     *
     * @param is The input stream to read the message from.
     * @return The message.
     * @throws IOException                   thrown if there's an error reading the message from the input stream.
     * @throws FieldDeserializationException thrown if an error occurs during serialization.
     */
    protected abstract U createUnencryptedMessage(LengthPrependedDataInputStream is)
        throws IOException, FieldDeserializationException;

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof EncryptedMessage<?>) {
            EncryptedMessage<?> other = (EncryptedMessage<?>) obj;
            return (getClass() == other.getClass() &&
                sessionId == other.sessionId &&
                Arrays.equals(encryptedData, other.encryptedData)) &&
                Arrays.equals(iv, other.iv);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sessionId, encryptedData, iv);
    }
}
