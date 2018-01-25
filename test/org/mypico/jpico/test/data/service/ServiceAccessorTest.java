package org.mypico.jpico.test.data.service;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceAccessor;
import org.mypico.jpico.test.util.Corrupter;

public abstract class ServiceAccessorTest {

    private DataFactory factory;
    private ServiceAccessor accessor;

    protected abstract DataFactory getFactory();

    protected abstract ServiceAccessor getAccessor();

    @Before
    public void setUp() throws Exception {
        factory = checkNotNull(getFactory());
        accessor = checkNotNull(getAccessor());
    }

    /*
     * Create and save a new Service instance, catching any exceptions so they don't interfere with
     * tests which expect exceptions.
     */
    private Service saveService(String mod) {
        Service s = ServiceTest.getService(factory, mod);
        try {
            s.save();
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while saving Service instance", e);
        }
        return s;
    }

    private Service saveService() {
        return saveService("");
    }

    @Test
    public void testGetServiceById() throws IOException {
        Service s = saveService();
        Service r = accessor.getServiceById(s.getId());
        assertNotNull(r);
        assertEquals(s, r);
    }

    @Test
    public void testGetServiceByIdFromMultiple() throws IOException {
        saveService("1");
        Service s = saveService("2");
        assertEquals(s, accessor.getServiceById(s.getId()));
    }

    @Test
    public void testGetServiceByIdNullWhenNone() throws IOException {
        assertNull(accessor.getServiceById(1));
    }

    @Test
    public void testGetServiceByIdNullWhenWrong() throws IOException {
        Service s = saveService();
        assertNull(accessor.getServiceById(s.getId() + 1));
    }

    @Test
    public void testGetServiceByCommitment() throws IOException {
        Service s = saveService();
        assertEquals(s, accessor.getServiceByCommitment(s.getCommitment()));
    }

    @Test
    public void testGetServiceByCommitmentNullWhenNone() throws IOException {
        assertNull(accessor.getServiceByCommitment(ServiceTest.COMMITMENT));
    }

    @Test
    public void testGetServiceByCommitmentNullWhenWrong()
            throws IOException {
        Service s = saveService();
        byte[] wrongCommitment = Corrupter.corrupt(s.getCommitment());
        assertNull(accessor.getServiceByCommitment(wrongCommitment));
    }
}
