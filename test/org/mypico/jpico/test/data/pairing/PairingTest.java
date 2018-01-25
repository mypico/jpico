package org.mypico.jpico.test.data.pairing;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingImpFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.test.data.TestDataFactory;
import org.mypico.jpico.test.data.service.ServiceTest;

public class PairingTest {

    public static final DataFactory DATA_FACTORY = new TestDataFactory();
    public static final PairingImpFactory FACTORY = DATA_FACTORY;
    public static final String NAME = "pairing name";
    public static final Service SERVICE = ServiceTest.getService();

    /**
     * Create a new {@link Pairing} instance with a new related {@link Service}. Catches any
     * exceptions thrown while creating the pairing and re-throws them as {@link RuntimeException}s
     * so they wont interfere with tests which expect certain exceptions to be thrown.
     * 
     * @param factory to construct the <code>Pairing</code> (and related <code>Service</code> with.
     * @param mod <code>String</code> to append to the default name of the pairing.
     * @return new <code>Pairing</code> instance.
     * @throws RuntimeException if any exception occurs while creating the new <code>Pairing</code>
     *         instance.
     */
    public static Pairing getPairing(DataFactory factory, String mod) {
        try {
            return new Pairing(
                    factory, NAME + mod, ServiceTest.getService(factory, mod));
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while creating Pairing instance", e);
        }
    }

    public static Pairing getPairing(DataFactory factory) {
        return getPairing(factory, "");
    }

    public static Pairing getPairing(String mod) {
        return getPairing(DATA_FACTORY, mod);
    }

    public static Pairing getPairing() {
        return getPairing(DATA_FACTORY, "");
    }

    @Test
    public void testConstructor() {
        assertNotNull(new Pairing(FACTORY, NAME, SERVICE));
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullImp() {
        new Pairing(null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullFactory() {
        new Pairing(null, NAME, SERVICE);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullName() {
        new Pairing(FACTORY, null, SERVICE);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullService() {
        new Pairing(FACTORY, NAME, null);
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullFactory() {
        Pairing p = new Pairing(FACTORY, NAME, SERVICE);
        new Pairing(null, p);
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullPairing() {
        new Pairing(FACTORY, null);
    }

    @Test(expected = NullPointerException.class)
    public void testSetNullName() {
        Pairing p = new Pairing(FACTORY, NAME, SERVICE);
        p.setName(null);
    }

    @Test(expected = NullPointerException.class)
    public void testCheckNameNull() {
        Pairing.checkName(null);
    }

    @Test(expected = IllegalStateException.class)
    public void testEqualsTwoUnsaved() {
        Pairing p1 = getPairing("1");
        Pairing p2 = getPairing("2");
        p1.equals(p2);
    }

    @Test
    public void testEqualsOneSaved() throws Exception {
        Pairing p1 = getPairing("1");
        Pairing p2 = getPairing("2");
        p1.save();
        p1.equals(p2);
    }

    @Test
    public void testEqualsTwoDifferentSaved() throws Exception {
        Pairing p1 = getPairing("1");
        Pairing p2 = getPairing("2");
        p1.save();
        p2.save();
        p1.equals(p2);
    }

    @Test
    public void testEqualsSelfSaved() throws Exception {
        Pairing p = getPairing();
        p.save();
        assertTrue(p.equals(p));
    }
}
