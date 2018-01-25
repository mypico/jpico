package org.mypico.jpico.test.data.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Test;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImpFactory;
import org.mypico.jpico.test.data.TestServiceImpFactory;

public class ServiceTest {

    public static final ServiceImpFactory FACTORY = new TestServiceImpFactory();
    public static final String NAME = "service name";
    public static final URI ADDRESS;
    private static final String COMMITMENT_STRING = "commitment";
    public static final byte[] COMMITMENT = COMMITMENT_STRING.getBytes();

    static {
        try {
            ADDRESS = new URI("http://serviceaddress.com/");
        } catch (URISyntaxException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * Create a new {@link Service} instance. Catches any exceptions thrown while creating the
     * service and re-throws them as {@link RuntimeException}s so they wont interfere with tests
     * which expect certain exceptions to be thrown.
     * 
     * @param factory to construct the <code>Service</code> with.
     * @param mod <code>String</code> to append to the default name, address and commitment of the
     *        service.
     * @return new <code>Service</code> instance.
     * @throws RuntimeException if any exception occurs while creating the new <code>Service</code>
     *         instance.
     */
    public static Service getService(ServiceImpFactory factory, String mod) {
        try {
            return new Service(
                    factory,
                    NAME + mod,
                    new URI(ADDRESS.toString() + mod),
                    (COMMITMENT_STRING + mod).getBytes());
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while creating Service instance", e);
        }
    }

    public static Service getService(ServiceImpFactory factory) {
        return getService(factory, "");
    }

    public static Service getService(String mod) {
        return getService(FACTORY, mod);
    }

    public static Service getService() {
        return getService(FACTORY, "");
    }

    @Test
    public void testConstructor() {
        assertNotNull(new Service(FACTORY, NAME, ADDRESS, COMMITMENT));
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullImp() {
        new Service(null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullFactory() {
        new Service(null, NAME, ADDRESS, COMMITMENT);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullName() {
        new Service(FACTORY, null, ADDRESS, COMMITMENT);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorEmptyName() {
        new Service(FACTORY, "", ADDRESS, COMMITMENT);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullAddress() {
        new Service(FACTORY, NAME, null, COMMITMENT);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorNullCommitment() {
        new Service(FACTORY, NAME, ADDRESS, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorEmptyCommitment() {
        new Service(FACTORY, NAME, ADDRESS, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullFactory() {
        new Service(null, getService());
    }

    @Test(expected = NullPointerException.class)
    public void testCopyConstructorNullService() {
        new Service(FACTORY, null);
    }

    @Test(expected = NullPointerException.class)
    public void testCheckNameNull() {
        Service.checkName(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCheckNameEmpty() {
        Service.checkName("");
    }

    @Test(expected = IllegalStateException.class)
    public void testEqualsTwoUnsaved() {
        Service s1 = getService("1");
        Service s2 = getService("2");
        s1.equals(s2);
    }

    @Test
    public void testEqualsOneSaved() throws Exception {
        Service s1 = getService("1");
        Service s2 = getService("2");
        s1.save();
        assertFalse(s1.equals(s2));
    }

    @Test
    public void testEqualsTwoDifferentSaved() throws Exception {
        Service s1 = getService("1");
        Service s2 = getService("2");
        s1.save();
        s2.save();
        assertFalse(s1.equals(s2));
    }

    @Test
    public void testEqualsSelfSaved() throws Exception {
        Service s = getService();
        s.save();
        assertTrue(s.equals(s));
    }
}
