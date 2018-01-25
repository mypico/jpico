package org.mypico.jpico.test.visualcode;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.Signature;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.test.data.service.ServiceTest;
import org.mypico.jpico.test.util.UsesCryptoTest;
import org.mypico.jpico.visualcode.KeyPairingVisualCode;

public class KeyPairingVisualCodeTest extends UsesCryptoTest {
    
    public static KeyPairingVisualCode getCode() {
        try {
            return KeyPairingVisualCode.getSignedInstance(
            		ServiceTest.ADDRESS,
            		new URI("http://rendezvous.example.com/channel/example"),
            		"terminalCommitment".getBytes(),
            		ServiceTest.NAME,
            		CryptoFactory.INSTANCE.ecKpg().generateKeyPair());
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured whilst creating visual code.", e);
        }
    }

    
    private KeyPairingVisualCode code;

    @Before
    public void setUp() throws Exception {
        code = getCode();
    }

    @Test
    public void testGetBytesToSign() throws Exception {
        // Get correct bytes to sign:
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        Charset utf8 = Charset.forName("UTF-8");
        os.write(code.getServiceName().getBytes(utf8));
        os.write(code.getServiceAddress().toString().getBytes(utf8));
        byte[] correctBytesToSign = os.toByteArray();

        // Test
        assertTrue(Arrays.equals(correctBytesToSign, code.getBytesToSign()));
    }

    @Test
    public void testSignature() throws Exception {
        Signature verifier = Signature.getInstance("SHA256WITHECDSA");
        verifier.initVerify(code.getServicePublicKey());

        // Update verifier with bytes to be signed in correct order
        Charset utf8 = Charset.forName("UTF-8");
        verifier.update(code.getServiceName().getBytes(utf8));
        verifier.update(code.getServiceAddress().toString().getBytes(utf8));

        // Verify
        assertTrue(verifier.verify(code.getSignature()));
    }

}
