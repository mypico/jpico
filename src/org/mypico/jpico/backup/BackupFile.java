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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.CryptoRuntimeException;

/**
 * Abstraction representing a backup of the Pico database.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public final class BackupFile {

    private final File dbFile;

    /**
     * Constructor that sets the database file.
     *
     * @param dbFile The file to use to store the backup.
     */
    private BackupFile(final File dbFile) {
        this.dbFile = dbFile;
    }

    /**
     * Factory for creating a new backup instance.
     *
     * @param dbFile The file to use to store the backup.
     * @return The <code>BackupFile</code> instance created.
     */
    public static BackupFile newInstance(final File dbFile) {
        // Verify the method's preconditions
        checkNotNull(dbFile);

        return new BackupFile(dbFile);
    }

    /**
     * Create an encrypted backup of the Pico pairings and services database.
     *
     * @param backupKey The key to use to encrypt the backup.
     * @return Encrypted backup file.
     * @throws FileNotFoundException if the file could not be created.
     * @throws IOException           if an error is generated creating the file.
     */
    public EncBackupFile createEncBackupFile(final BackupKey backupKey)
        throws FileNotFoundException, IOException {
        // Verify the method's preconditions
        checkNotNull(backupKey);

        try {
            final FileInputStream fileIs = new FileInputStream(dbFile);
            byte[] plaintext = new byte[(int) dbFile.length()];
            try {
                fileIs.read(plaintext);
                fileIs.close();

                final Cipher cipher = CryptoFactory.INSTANCE.aes256();
                cipher.init(Cipher.ENCRYPT_MODE, backupKey.getSecretKey());
                final byte[] ciphertext = cipher.doFinal(plaintext);

                final ByteArrayInputStream cipherIs = new ByteArrayInputStream(ciphertext);
                final byte[] encryptedData = new byte[cipherIs.available()];
                cipherIs.read(encryptedData);

                return new EncBackupFile(encryptedData, cipher.getIV());
            } finally {
                fileIs.close();
            }
        } catch (InvalidKeyException e) {
            throw new CryptoRuntimeException();
        } catch (BadPaddingException e) {
            throw new CryptoRuntimeException();
        } catch (IllegalBlockSizeException e) {
            throw new CryptoRuntimeException();
        }
    }

    /**
     * Get the File for backup storage.
     *
     * @return The File.
     */
    public File getDbFile() {
        return dbFile;
    }
}