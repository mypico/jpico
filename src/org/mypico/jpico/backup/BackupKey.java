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

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.mypico.jpico.crypto.CryptoFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstraction representing the key used to encrypt a backup of the Pico pairings and
 * services database.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public abstract class BackupKey {

    private static final Logger LOGGER = LoggerFactory.getLogger(
        BackupKey.class.getSimpleName());
    private static final int BACKUP_USER_SECRET_LENGTH = 12;

    protected final byte[] userSecret = new byte[BACKUP_USER_SECRET_LENGTH];
    private final SecretKey secretKey;

    /**
     * Generate a new random BackupKey key
     */
    protected BackupKey() {
        // Generate the random 96 bytes to be remember by the user,
        // this is used to generate the 128-bit AES key
        final SecureRandom random = new SecureRandom();
        random.nextBytes(userSecret);

        final MessageDigest urkbImage = CryptoFactory.INSTANCE.sha256();
        urkbImage.update(userSecret);
        secretKey = new SecretKeySpec(urkbImage.digest(), "AES");
    }

    /**
     * Generate a AES key from the userSecret.
     *
     * @param userSecret The user secret.
     * @throws BackupKeyInvalidLengthException thrown in case the key has an invalid length.
     */
    protected BackupKey(final byte[] userSecret) throws BackupKeyInvalidLengthException {
        // Verify the method's preconditions
        checkNotNull(userSecret, "userSecret cannot be null");

        if (userSecret.length != BACKUP_USER_SECRET_LENGTH) {
            LOGGER.error("Length of user secret ({}) is != {}",
                userSecret.length, BACKUP_USER_SECRET_LENGTH);
            throw new BackupKeyInvalidLengthException();
        }

        // Store the userSecret (the preimage)
        System.arraycopy(userSecret, 0, this.userSecret, 0, BACKUP_USER_SECRET_LENGTH);

        // Generate a key, by hashing the userSecret (preimage)
        final MessageDigest urkbImage = CryptoFactory.INSTANCE.sha256();
        urkbImage.update(this.userSecret);
        secretKey = new SecretKeySpec(urkbImage.digest(), "AES");
    }

    /**
     * Check whether the userSecret is valid. Specifically, it checks the length of the key
     * is as required.
     *
     * @param userSecret The user secret.
     * @return true if the key is valid, false o/w.
     */
    public static boolean isValid(final byte[] userSecret) {
        if (userSecret.length != BACKUP_USER_SECRET_LENGTH) {
            return false;
        }
        return true;
    }

    /**
     * Accessor method for the BackupKey instances userSecret.
     *
     * @return The userSecret (as a byte[]).
     */
    public byte[] getUserSecret() {
        return userSecret;
    }

    /**
     * Accessor method for the BackupKey instances secretKey.
     *
     * @return The SecretKey instance.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }
}