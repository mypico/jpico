package org.mypico.jpico.test.crypto.messages;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.security.InvalidKeyException;
import java.security.SignatureException;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.mypico.jpico.crypto.messages.EncryptedMessage;
import org.mypico.jpico.crypto.messages.UnencryptedMessage;


public abstract class UnencryptedMessageTest extends MessageTest {

    protected abstract UnencryptedMessage<?> getInstance() throws InvalidKeyException, SignatureException;

    @Test
    public final void testEncryptDecrypt() throws Exception {
        UnencryptedMessage<?> m1 = getInstance();
        SecretKey k = encKg.generateKey();
        UnencryptedMessage<?> m2 = m1.encrypt(k).decrypt(k);
        assertEquals(m1, m2);
    }

    @Test
    public final void testDecryptEncrypt() throws Exception {
        SecretKey k = encKg.generateKey();
        EncryptedMessage<?> e = getInstance().encrypt(k);
        EncryptedMessage<?> e2 = e.decrypt(k).encrypt(k);
        assertNotNull(e);
        assertNotNull(e2);
        // The different IV should mean the same message encrypted, decrypted
        // and then re-encrypted, gives two different encrypted representations.
        assertFalse(e.equals(e2));
    }
}
