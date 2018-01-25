package org.mypico.jpico.test.data.pairing;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.pairing.KeyPairingAccessor;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.test.data.service.ServiceTest;
import org.mypico.jpico.test.util.UsesCryptoTest;

public abstract class KeyPairingAccessorTest extends UsesCryptoTest {


    private DataFactory factory;
    private KeyPairingAccessor accessor;

    protected abstract DataFactory getFactory();

    protected abstract KeyPairingAccessor getAccessor();

    /*
     * Create a new KeyPairing instance, catching any exceptions so they don't interfere with tests
     * which expect exceptions.
     */
    private KeyPairing getPairing(String name) {
        try {
            Service s = ServiceTest.getService(factory);
			return new KeyPairing(factory, name, s, CryptoFactory.INSTANCE.ecKpg()
					.generateKeyPair(), "");
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while creating KeyPairing instance", e);
        }
    }

    /*
     * Create and save a new KeyPairing instance, catching any exceptions so they don't interfere
     * with tests which expect exceptions.
     */
    private KeyPairing savePairing(String name) {
        KeyPairing p = getPairing(name);
        try {
            p.save();
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while saving KeyPairing instance", e);
        }
        return p;
    }
    
    private KeyPairing savePairing() {
    	return savePairing("pairing");
    }

    @Before
    public void setUp() throws Exception {
        factory = checkNotNull(getFactory());
        accessor = checkNotNull(getAccessor());
    }

    @Test
    public void testGetKeyPairingById() throws IOException {
        KeyPairing kp = savePairing();
        KeyPairing r = accessor.getKeyPairingById(kp.getId());
        assertNotNull(r);
        assertEquals(kp, r);
    }

    @Test
    public void testGetKeyPairingsByServiceCommitment() {
        //TODO fail("Not yet implemented");
    }

}
