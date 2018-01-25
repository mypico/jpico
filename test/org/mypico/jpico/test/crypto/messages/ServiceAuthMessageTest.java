package org.mypico.jpico.test.crypto.messages;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.crypto.messages.ServiceAuthMessage;

public class ServiceAuthMessageTest extends UnencryptedMessageTest {

    private int sessionId;
    private PublicKey serviceEphemeralPublicKey;
    private Nonce serviceNonce;
    private Nonce picoNonce;
    private KeyPair serviceIdentityKey;
    private SecretKey serviceMacKey;

    @Before
    public void setUp() throws Exception {
        sessionId = 1;
		serviceEphemeralPublicKey = CryptoFactory.INSTANCE.ecKpg().genKeyPair().getPublic();
        serviceNonce = Nonce.getRandomInstance();
        picoNonce = Nonce.getRandomInstance();
		serviceIdentityKey = CryptoFactory.INSTANCE.ecKpg().genKeyPair();
        serviceMacKey = macKg.generateKey();
    }

    @Test
    public void testGetInstance() throws InvalidKeyException, SignatureException {
        ServiceAuthMessage instance = ServiceAuthMessage.getInstance(
        		sessionId, serviceEphemeralPublicKey, serviceNonce, picoNonce, serviceIdentityKey, 
        		serviceMacKey);

        // Assert simple values instantiated correctly
        assertEquals(sessionId, instance.getSessionId());
        assertEquals(serviceEphemeralPublicKey,
                instance.getServiceEphemeralPublicKey());
        assertEquals(serviceNonce, instance.getServiceNonce());
        assertEquals(serviceIdentityKey.getPublic(), instance.getServicePublicKey());

        // Get bytes to be verified
        // picoNonce||sessionId||serviceEphemeralPublicKey
        final byte[] bytesToVerify;

        byte[] picoNonceBytes = picoNonce.getValue();
        byte[] sessionIdBytes = ByteBuffer.allocate(4).putInt(sessionId).array();
        byte[] serviceEphemeralPublicKeyBytes = serviceEphemeralPublicKey.getEncoded();
        int numBytes =
                picoNonceBytes.length + sessionIdBytes.length
                        + serviceEphemeralPublicKeyBytes.length;

        ByteBuffer byteBuffer = ByteBuffer.allocate(numBytes);
        byteBuffer.put(picoNonceBytes);
        byteBuffer.put(sessionIdBytes);
        byteBuffer.put(serviceEphemeralPublicKeyBytes);

        bytesToVerify = byteBuffer.array();

        // Verify signature using the service's long-term public key:
        Signature verifier = CryptoFactory.INSTANCE.sha256Ecdsa();
        verifier.initVerify(serviceIdentityKey.getPublic());
        verifier.update(bytesToVerify);
        assertTrue(verifier.verify(instance.getSignature()));

        // Check the MAC of the service's long-term public key
        Mac macer = CryptoFactory.INSTANCE.sha256Hmac();
        macer.init(serviceMacKey);
        macer.update(serviceIdentityKey.getPublic().getEncoded());
        Assert.assertArrayEquals(macer.doFinal(), instance.getMac());
    }

    @Override
    protected ServiceAuthMessage getInstance() throws InvalidKeyException, SignatureException {
        return ServiceAuthMessage.getInstance(
        		sessionId, serviceEphemeralPublicKey, serviceNonce, picoNonce, serviceIdentityKey, 
        		serviceMacKey);
    }
}
