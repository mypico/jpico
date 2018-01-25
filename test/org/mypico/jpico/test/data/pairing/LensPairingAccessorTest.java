package org.mypico.jpico.test.data.pairing;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.LensPairingAccessor;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.test.data.service.ServiceTest;

public abstract class LensPairingAccessorTest {

    private DataFactory factory;
    @SuppressWarnings("unused")
	private LensPairingAccessor accessor;

    protected abstract DataFactory getFactory();

    protected abstract LensPairingAccessor getAccessor();

    /*
     * Create a new LensPairing instance, catching any exceptions so they don't interfere with tests
     * which expect exceptions.
     */
    private LensPairing getPairing(String name, String service, List<String> privateFields) {
        try {
            Service s = ServiceTest.getService(factory, service);
            Map<String, String> cs = new HashMap<String, String>();
            cs.put("foo", "bar");
            return new LensPairing(factory, name, s, cs, privateFields);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while creating LensPairing"
                            + " instance", e);
        }
    }

    /*
     * Create and save a new LensPairing instance, catching any exceptions so they don't interfere
     * with tests which expect exceptions.
     */
    private LensPairing savePairing(String name, String service) {
    	return savePairing(name, service, Arrays.asList(name));
    }

    
	private LensPairing savePairing(String name, String service, List<String> privateFields) {
        LensPairing p = getPairing(name, service, privateFields);
        try {
            p.save();
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while saving LensPairing"
                            + " instance", e);
        }
        return p;
    }

    @Before
    public void setUp() throws Exception {
        factory = checkNotNull(getFactory());
        accessor = checkNotNull(getAccessor());
    }

    @Test
    public void testGetLensPairingById() throws IOException {
    	LensPairing p = savePairing("1", "Service");
    	LensPairing r = accessor.getLensPairingById(p.getId());
        assertNotNull(r);
        assertEquals(p, r);
    }

    @Test
    public void testGetLensPairingsByServiceCommitment() throws IOException {
    	// Create pairings
    	LensPairing p1 = savePairing("1", "Service1");
    	LensPairing p2 = savePairing("2", "Service1");
    	LensPairing p3 = savePairing("3", "Service2");
    	
    	// Get pairings for service 1
    	List<LensPairing> r = accessor.getLensPairingsByServiceCommitment(ServiceTest.getService(factory, "Service1").getCommitment());
    	assertNotNull(r);
        assertEquals(2, r.size());
        assertEquals(p1, r.get(0));
        assertEquals(p2, r.get(1));
        
        // Get pairings for service 2
        r = accessor.getLensPairingsByServiceCommitment(ServiceTest.getService(factory, "Service2").getCommitment());
    	assertNotNull(r);
        assertEquals(1, r.size());
        assertEquals(p3, r.get(0));        
    }
    
    // https://gitlab.dtg.cl.cam.ac.uk/pico/jpico/issues/9
    @Test
    public void testCreateLensPairingWithSamePrivateFields() throws IOException {
    	LensPairing p1 = savePairing("1", "Service1", Arrays.asList("private"));
    	LensPairing p2 = savePairing("2", "Service2", Arrays.asList("private"));
    	
    	LensPairing r = accessor.getLensPairingById(p1.getId());
    	assertNotNull(r);
        assertEquals(p1, r);
    
        r = accessor.getLensPairingById(p2.getId());
    	assertNotNull(r);
        assertEquals(p2, r);
        
    }

}
