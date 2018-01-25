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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

/**
 * Provide factory methods for generating objects for performing basic cryptographic functions.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public enum CryptoFactory {
    INSTANCE;

    public static final ECGenParameterSpec PRIME192V1 = new ECGenParameterSpec("prime192v1");
    public static final String HMAC_SHA256 = "Hmac-SHA256";
    public static final String SHA256_ECDSA = "SHA256WITHECDSA";
    public static final String AES = "AES";
    public static final String AES_GCM = "AES/GCM/NoPadding";

    private final Provider bcProvider;

    /**
     * Constructor.
     */
    private CryptoFactory() {
        // Use SpongyCastle if present (overriding the reduced android one), otherwise use
        // BouncyCastle
        Provider provider = Security.getProvider("SC");
        if (provider == null) {
            provider = Security.getProvider("BC");
        }
        bcProvider = checkNotNull(provider, "Neither BouncyCastle nor spongycastle provider found");
    }

    /**
     * Forge an asymmetric EC key pair generator.
     *
     * @return the key pair generator.
     */
    public KeyPairGenerator ecKpg() {
        try {
            // Get the KeyPairGenerator
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", bcProvider);

            // Initialise with the curve specification
            kpg.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());

            return kpg;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge an ECDH key agreement object.
     *
     * @return the ECDH object.
     */
    public KeyAgreement ecKeyAgreement() {
        try {
            return KeyAgreement.getInstance("ECDH", bcProvider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge a SHA-256 hash creator object.
     *
     * @return the hash creator object.
     */
    public MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge a SHA256-HMAC generator object.
     *
     * @return the SHA256-HMAC generator object.
     */
    public Mac sha256Hmac() {
        try {
            return Mac.getInstance(HMAC_SHA256, bcProvider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge a SHA256-ECDSA generator object.
     *
     * @return the SHA256-ECDSA generator object.
     */
    public Signature sha256Ecdsa() {
        try {
            return Signature.getInstance(SHA256_ECDSA, bcProvider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge an AES256 key generator object.
     *
     * @return the AES256 key generator object.
     */
    public KeyGenerator aes256Kg() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(AES, bcProvider);
            kg.init(256);
            return kg;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge an AES256 cipher generator object.
     *
     * @return the AES256 cipher generator object.
     */
    public Cipher aes256() {
        try {
            return Cipher.getInstance(AES_GCM, bcProvider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge a SHA256-HMAC key generator object.
     *
     * @return the SHA256-HMAC key generator object.
     */
    public KeyGenerator sha256HmacKg() {
        try {
            return KeyGenerator.getInstance(HMAC_SHA256, bcProvider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    /**
     * Forge an asymmetric EC key factor object.
     *
     * @return the EC key factor object.
     */
    public KeyFactory ecKeyFactory() {
        try {
            return KeyFactory.getInstance("EC", bcProvider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }
}
