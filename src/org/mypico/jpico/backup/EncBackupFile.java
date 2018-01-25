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


package org.mypico.jpico.backup;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.io.ByteStreams.copy;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

import org.mypico.jpico.crypto.CryptoFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstraction representing an encrypted backup of the Pico database.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public final class EncBackupFile {

    private static final Logger LOGGER = LoggerFactory.getLogger(
        EncBackupFile.class.getSimpleName());

    private final byte[] encryptedData;
    private final byte[] iv;

    /**
     * Constructor that stores the encrypted data and iv for the backup.
     *
     * @param encryptedData The encrypted data.
     * @param iv            The iv.
     */
    public EncBackupFile(final byte[] encryptedData, final byte[] iv) {
        this.encryptedData = encryptedData;
        this.iv = iv;
    }

    /**
     * Create an unencrypted copy of the back up file.
     *
     * @param dbFile    The backup file.
     * @param backupKey The key used to encrypt the backup.
     * @return the decrypted backup.
     * @throws FileNotFoundException         thrown if the specified backup file doesn't exist.
     * @throws IOException                   thown if there's an error reading the backup file.
     * @throws BackupKeyInvalidException     thrown if the key is invalid for this backup file.
     * @throws BackupFileDecryptionException thrown if there's an error decrypting the file.
     */
    public BackupFile createUnencryptedBackupFile(final File dbFile, final BackupKey backupKey)
        throws FileNotFoundException, IOException, BackupKeyInvalidException,
        BackupFileDecryptionException {
        // Verify the method's preconditions
        checkNotNull(dbFile);
        checkNotNull(backupKey);

        final Cipher cipher = CryptoFactory.INSTANCE.aes256();
        final IvParameterSpec ips = new IvParameterSpec(iv);

        try {
            cipher.init(Cipher.DECRYPT_MODE, backupKey.getSecretKey(), ips);
            final byte[] decryptedData = cipher.doFinal(encryptedData);
            final ByteArrayInputStream cipherIs = new ByteArrayInputStream(decryptedData);
            try {
                if (!dbFile.exists()) {
                    dbFile.getParentFile().mkdirs();
                    dbFile.createNewFile();
                }

                final FileOutputStream outputStream = new FileOutputStream(dbFile);
                try {
                    // Guava ByteStreams.copy() does not flush or close either stream
                    copy(cipherIs, outputStream);
                    outputStream.flush();
                    return BackupFile.newInstance(dbFile);
                } finally {
                    outputStream.close();
                }
            } finally {
                cipherIs.close();
            }
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.error("Failure decrypting Pico database backup", e);
            throw new BackupFileDecryptionException();
        } catch (IllegalBlockSizeException e) {
            // Decryption failure
            LOGGER.error("Failure decrypting Pico database", e);
            throw new BackupFileDecryptionException();
        } catch (BadPaddingException e) {
            // BadPaddingException (authenticated encryption MAC failure)
            LOGGER.error("Authenticated encryption failure", e);
            throw new BackupFileDecryptionException();
        } catch (InvalidKeyException e) {
            // Backup key is invalid
            LOGGER.error("Backup key is invalid", e);
            throw new BackupKeyInvalidException("BackupKey is invalid");
        }
    }

    /**
     * Accessor method for the instance's encryptedData attribute.
     *
     * @return The encrypted data.
     */
    public byte[] getEncryptedData() {
        return encryptedData;
    }

    /**
     * Accessor method for the instance's iv attribute.
     *
     * @return The initialization vector (IV) used to encrypt the backup file.
     */
    public byte[] getIv() {
        return iv;
    }
}