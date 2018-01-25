package org.mypico.jpico.test.data.pairing;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.pairing.KeyPairingImpFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.test.data.TestKeyPairingImpFactory;
import org.mypico.jpico.test.data.service.ServiceTest;
import org.mypico.jpico.test.util.UsesCryptoTest;

public class KeyPairingTest extends UsesCryptoTest {

    private KeyPairingImpFactory factory;
    private Service service;
    private final String name = "name";
    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    @Before
    public void setUp() throws Exception {
        factory = new TestKeyPairingImpFactory();
        service = ServiceTest.getService();
		keyPair = CryptoFactory.INSTANCE.ecKpg().generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    private KeyPairing getKeyPairing(String mod) {
        try {
            return new KeyPairing(factory, name + mod, service, keyPair, "");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private KeyPairing getKeyPairing() {
        return getKeyPairing("");
    }

    @Test
    public void testConstructorSeparateKeys() {
        assertNotNull(new KeyPairing(factory, name, service, publicKey, privateKey, ""));
    }

    @Test
    public void testConstructorKeyPair() {
        assertNotNull(new KeyPairing(factory, name, service, keyPair, ""));
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullImp() {
        new KeyPairing(null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullFactory() {
        new KeyPairing(null, name, service, keyPair, "");
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullName() {
        new KeyPairing(factory, null, service, keyPair, "");
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullService() {
        new KeyPairing(factory, name, null, keyPair, "");
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullPublicKey() {
        new KeyPairing(factory, name, null, null, privateKey, "");
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullPrivateKey() {
        new KeyPairing(factory, name, null, publicKey, null, "");
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullFactory() {
        new KeyPairing(null, getKeyPairing());
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullPairing() {
        new KeyPairing(factory, null);
    }

    @Test(expected = NullPointerException.class)
    public void testSetNullName() {
        KeyPairing p = getKeyPairing();
        p.setName(null);
    }

    @Test(expected = IllegalStateException.class)
    public void testEqualsTwoUnsaved() {
        KeyPairing p1 = getKeyPairing("1");
        KeyPairing p2 = getKeyPairing("2");
        p1.equals(p2);
    }

    @Test
    public void testEqualsOneSaved() throws Exception {
        KeyPairing p1 = getKeyPairing("1");
        KeyPairing p2 = getKeyPairing("2");
        p1.save();
        p1.equals(p2);
    }

    @Test
    public void testEqualsTwoDifferentSaved() throws Exception {
        KeyPairing p1 = getKeyPairing("1");
        KeyPairing p2 = getKeyPairing("2");
        p1.save();
        p2.save();
        p1.equals(p2);
    }

    @Test
    public void testEqualsSelfSaved() throws Exception {
        KeyPairing p1 = getKeyPairing();
        p1.save();
        assertTrue(p1.equals(p1));
    }
}
