package org.mypico.jpico.test.data.pairing;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.LensPairingImpFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.test.data.TestLensPairingImpFactory;
import org.mypico.jpico.test.data.service.ServiceTest;
import org.mypico.jpico.test.util.UsesCryptoTest;

public class LensPairingTest extends UsesCryptoTest {

    private static final Map<String, String> EMPTY =
            new HashMap<String, String>();

    private LensPairingImpFactory factory;
    private Service service;
    private final String name = "name";
    private Map<String, String> credentials;
    private List<String> privateFields;

    @Before
    public void setUp() throws Exception {
        factory = new TestLensPairingImpFactory();
        service = ServiceTest.getService();
        credentials = new HashMap<String, String>(2);
        credentials.put("username", "foo");
        credentials.put("password", "bar");
		privateFields = new ArrayList<String>();
    }

    private LensPairing getLensPairing(String mod) {
        try {
            return new LensPairing(
                    factory, name + mod, service, credentials, privateFields);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private LensPairing getLensPairing() {
        return getLensPairing("");
    }

    @Test
    public void testConstructor() {
        assertNotNull(new LensPairing(factory, name, service, credentials, privateFields));
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullImp() {
        new LensPairing(null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullFactory() {
        new LensPairing(null, name, service, credentials, privateFields);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullName() {
        new LensPairing(factory, null, service, credentials, privateFields);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullService() {
        new LensPairing(factory, name, null, credentials, privateFields);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullCredentials() {
        new LensPairing(factory, name, service, null, privateFields);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorEmptyCredentials() {
        new LensPairing(factory, name, service, EMPTY, privateFields);
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullFactory() {
        new LensPairing(null, getLensPairing());
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullPairing() {
        new LensPairing(factory, null);
    }

    @Test(expected = NullPointerException.class)
    public void testSetNullName() {
        LensPairing p = getLensPairing();
        p.setName(null);
    }

    @Test(expected = IllegalStateException.class)
    public void testEqualsTwoUnsaved() {
        LensPairing p1 = getLensPairing("1");
        LensPairing p2 = getLensPairing("2");
        p1.equals(p2);
    }

    @Test
    public void testEqualsOneSaved() throws Exception {
        LensPairing p1 = getLensPairing("1");
        LensPairing p2 = getLensPairing("2");
        p1.save();
        p1.equals(p2);
    }

    @Test
    public void testEqualsTwoDifferentSaved() throws Exception {
        LensPairing p1 = getLensPairing("1");
        LensPairing p2 = getLensPairing("2");
        p1.save();
        p2.save();
        p1.equals(p2);
    }

    @Test
    public void testEqualsSelfSaved() throws Exception {
        LensPairing p1 = getLensPairing();
        p1.save();
        assertTrue(p1.equals(p1));
    }
}
