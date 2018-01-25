package org.mypico.jpico.test.util;

import java.lang.reflect.Constructor;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.mypico.jpico.crypto.Nonce;

public class Corrupter {

    private static KeyFactory kf = null;

    static {
        try {
            kf = KeyFactory.getInstance("ECDSA", "BC");
        } catch (NoSuchAlgorithmException e) {
        } catch (NoSuchProviderException e) {
        }
    }

    public static PublicKey corrupt(PublicKey publicKey) {
        PublicKey corruptPublicKey = null;
        while (corruptPublicKey == null) {
            try {
                byte[] keyBits = publicKey.getEncoded();
                corruptOneBitInPlace(keyBits);
                corruptPublicKey =
                        kf.generatePublic(new X509EncodedKeySpec(keyBits));
            } catch (InvalidKeySpecException e) {
                corruptPublicKey = null;
            }
        }
        return corruptPublicKey;
    }

    public static Nonce corrupt(Nonce n) {
        try {
            byte[] ns = n.getValue();
            corruptOneBitInPlace(ns);
            Constructor<Nonce> constructor =
                    Nonce.class.getDeclaredConstructor(byte[].class);
            constructor.setAccessible(true);
            Nonce corruptNonce = constructor.newInstance(ns);
            return corruptNonce;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] corrupt(byte[] b) {
        byte[] bad = b.clone();
        corruptOneBitInPlace(bad);
        return bad;
    }

    public static void corruptOneBitInPlace(byte[] encodedKey) {
        SecureRandom r = new SecureRandom();
        int position = r.nextInt(encodedKey.length);
        int bit = r.nextInt(8);
        byte byteMask = (byte) (1 << bit);
        encodedKey[position] = (byte) (encodedKey[position] ^ byteMask);

    }
}
