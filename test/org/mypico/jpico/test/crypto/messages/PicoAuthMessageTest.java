package org.mypico.jpico.test.crypto.messages;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.crypto.messages.PicoAuthMessage;
import org.mypico.jpico.test.util.Corrupter;

public class PicoAuthMessageTest extends UnencryptedMessageTest {

    PicoAuthMessage instance;

    private int sessionId;
    private PublicKey picoEphemeralPublicKey;
    private Nonce serviceNonce;
    private KeyPair picoAccountIdentityKeyPair;
    private SecretKey picoMacKey;
    private byte[] extraData;

    @Before
    public void setUp() throws Exception {
        sessionId = 1;
        serviceNonce = Nonce.getRandomInstance();
		picoEphemeralPublicKey = CryptoFactory.INSTANCE.ecKpg().genKeyPair().getPublic();
		picoAccountIdentityKeyPair = CryptoFactory.INSTANCE.ecKpg().genKeyPair();
        picoMacKey = macKg.generateKey();
        extraData = "some extra data".getBytes();

        instance = getNewPicoAuthMessageInstance();
    }

    private PicoAuthMessage getNewPicoAuthMessageInstance() throws Exception {
        return PicoAuthMessage.getInstance(
                sessionId,
                serviceNonce,
                picoEphemeralPublicKey,
                picoAccountIdentityKeyPair, 
                picoMacKey,
                extraData);
    }

    @Test
    public void testGetInstance() {
        try {
            assertNotNull(instance);

            // Assert simple values instantiated correctly
            assertEquals(sessionId, instance.getSessionId());

            // Assert that the PicoAccountIdentityPublicKey was instantiated properly
            assertTrue(Arrays.equals(
                    this.picoAccountIdentityKeyPair.getPublic().getEncoded(),
                    instance.getPicoAccountIdentityPublicKey().getEncoded()));

            // Get the bytes to be verified:
            // serviceNonce||sessionId||picoEphemeralPublicKey
            final byte[] bytesToVerify;

            byte[] serviceNonceBytes = serviceNonce.getValue();
            byte[] sessionIdBytes = ByteBuffer.allocate(4).putInt(sessionId).array();
            byte[] picoEphemeralPublicKeyBytes = picoEphemeralPublicKey.getEncoded();
            int numBytes =
                    serviceNonceBytes.length + sessionIdBytes.length
                            + picoEphemeralPublicKeyBytes.length;

            ByteBuffer byteBuffer = ByteBuffer.allocate(numBytes);
            byteBuffer.put(serviceNonceBytes);
            byteBuffer.put(sessionIdBytes);
            byteBuffer.put(picoEphemeralPublicKeyBytes);

            bytesToVerify = byteBuffer.array();

            // Verify using the Pico's long-term private key
            Signature verifier = Signature.getInstance("SHA256WITHECDSA", "BC"); // TODO: Check
            verifier.initVerify(picoAccountIdentityKeyPair.getPublic());
            verifier.update(bytesToVerify);
            assertTrue(verifier.verify(instance.getSignature()));

            // Make the MAC of the service's long-term public key, using the
            // service's MAC key for this session:
            Mac macer = Mac.getInstance("HMACSHA256", "BC"); // TODO: Check
            macer.init(picoMacKey);
            macer.update(picoAccountIdentityKeyPair.getPublic().getEncoded());
            Assert.assertArrayEquals(macer.doFinal(), instance.getMac());
        } catch (InvalidKeyException e) {
            fail(e.toString());
        } catch (NoSuchAlgorithmException e) {
            fail(e.toString());
        } catch (NoSuchProviderException e) {
            fail(e.toString());
        } catch (SignatureException e) {
            fail(e.toString());
        }
    }

    @Test
    public void testVerify() throws Exception {
        assertTrue(instance.verify(serviceNonce, picoMacKey, picoEphemeralPublicKey));

        SecretKey k = encKg.generateKey();
        final PicoAuthMessage instance2 = instance.encrypt(k).decrypt(k);

        assertTrue(instance2.verify(serviceNonce, picoMacKey, picoEphemeralPublicKey));
    }

    @Test
    public void testVerifyFailMacWrong() throws Exception {
        final PicoAuthMessage instance2 = getNewPicoAuthMessageInstance();
        final Field picoAuthMessageMac = PicoAuthMessage.class
                .getDeclaredField("mac");
        picoAuthMessageMac.setAccessible(true);

        byte[] mac = (byte[]) picoAuthMessageMac.get(instance2);
        picoAuthMessageMac.set(instance2, Corrupter.corrupt(mac));

        assertFalse(instance2.verify(serviceNonce, picoMacKey, picoEphemeralPublicKey));
    }

    @Test
    public void testVerifyFailSignatureBad() throws Exception {
        final PicoAuthMessage instance2 = getNewPicoAuthMessageInstance();
        final Field picoAuthMessageSignature = PicoAuthMessage.class
                .getDeclaredField("signature");
        picoAuthMessageSignature.setAccessible(true);

        byte[] signature = (byte[]) picoAuthMessageSignature.get(instance2);

        boolean parsableSignature = false;
        while (!parsableSignature) {
            picoAuthMessageSignature.set(instance2, Corrupter.corrupt(signature));
            try {
                assertFalse(instance2.verify(serviceNonce, picoMacKey, picoEphemeralPublicKey));
                parsableSignature = true;
            } catch (SignatureException e) {

            }

        }

    }

    @Test
    public void testVerifyFailWhenSignedWithWrongIdentityKey() throws Exception {
        final PicoAuthMessage instance2 = getNewPicoAuthMessageInstance();
        final Field picoAccountIdentityPublicKey = PicoAuthMessage.class
                .getDeclaredField("picoAccountIdentityPublicKey");
        picoAccountIdentityPublicKey.setAccessible(true);

        PublicKey picoAccountIdentity = (PublicKey) picoAccountIdentityPublicKey.get(instance2);
        picoAccountIdentityPublicKey.set(instance2, Corrupter.corrupt(picoAccountIdentity));

        assertFalse(instance2.verify(serviceNonce, picoMacKey, picoEphemeralPublicKey));
    }

    @Override
    protected PicoAuthMessage getInstance() {
        return instance;
    }
}
