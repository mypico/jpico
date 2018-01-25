package org.mypico.jpico.test.data.pairing;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingAccessor;

public abstract class PairingAccessorTest {

    private DataFactory factory;
    private PairingAccessor accessor;

    protected abstract DataFactory getFactory();

    protected abstract PairingAccessor getAccessor();

    @Before
    public void setUp() throws Exception {
        factory = checkNotNull(getFactory());
        accessor = checkNotNull(getAccessor());
    }

    /*
     * Create and save a new Pairing instance, catching any exceptions so they don't interfere with
     * tests which expect exceptions.
     */
    private Pairing savePairing(String mod) {
        Pairing p = PairingTest.getPairing(factory, mod);
        try {
            p.save();
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while saving Pairing instance", e);
        }
        return p;
    }

    private Pairing savePairing() {
        return savePairing("");
    }

    @Test
    public void testGetPairingById() throws IOException {
        Pairing p = savePairing();
        Pairing r = accessor.getPairingById(p.getId());
        assertNotNull(r);
        assertEquals(p, r);
    }

    @Test
    public void testGetPairingByIdNullWhenNone() throws IOException {
        assertNull(accessor.getPairingById(1));
    }

    @Test
    public void testGetPairingByIdNullWhenWrong() throws IOException {
        Pairing p = savePairing();
        assertNull(accessor.getPairingById(p.getId() + 1));
    }
}
