package org.mypico.jpico.test.data.terminal;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.data.terminal.Terminal;
import org.mypico.jpico.test.util.Corrupter;
import org.mypico.jpico.test.util.UsesCryptoTest;

public abstract class TerminalAccessorTest extends UsesCryptoTest {

	private Terminal.ImpFactory factory;
	private Terminal.Accessor accessor;
	
	protected abstract Terminal.ImpFactory getFactory();
	protected abstract Terminal.Accessor getAccessor();
	
	@Before
	public void setUp() throws Exception {
		factory = checkNotNull(getFactory(), "subclass must supply a factory");
		accessor = checkNotNull(getAccessor(), "subclass must supply an accessor");
	}
	
	private Terminal saveTerminal(String mod) {
		Terminal t = TerminalTest.getTerminal(factory, mod);
		try {
			t.save();
		} catch (Exception e) {
			throw new RuntimeException("exception while saving terminal", e);
		}
		return t;
	}
	
	private Terminal saveTerminal() {
		return saveTerminal("");
	}
	
	@Test
    public void testGetTerminalById() throws IOException {
        Terminal t = saveTerminal();
        Terminal r = accessor.getTerminalById(t.getId());
        assertNotNull(r);
        assertEquals(t, r);
    }

    @Test
    public void testGetTerminalByIdFromMultiple() throws IOException {
        saveTerminal("1");
        Terminal t = saveTerminal("2");
        assertEquals(t, accessor.getTerminalById(t.getId()));
    }

    @Test
    public void testGetTerminalByIdNullWhenNone() throws IOException {
        assertNull(accessor.getTerminalById(1));
    }

    @Test
    public void testGetTerminalByIdNullWhenWrong() throws IOException {
        Terminal t = saveTerminal();
        assertNull(accessor.getTerminalById(t.getId() + 1));
    }

    @Test
    public void testGetTerminalByCommitment() throws IOException {
        Terminal t = saveTerminal();
        assertEquals(t, accessor.getTerminalByCommitment(t.getCommitment()));
    }

    @Test
    public void testGetTerminalByCommitmentNullWhenNone() throws IOException {
        assertNull(accessor.getTerminalByCommitment(
        		TerminalTest.DEFAULT_COMMITMENT));
    }

    @Test
    public void testGetTerminalByCommitmentNullWhenWrong()
            throws IOException {
        Terminal s = saveTerminal();
        byte[] wrongCommitment = Corrupter.corrupt(s.getCommitment());
        assertNull(accessor.getTerminalByCommitment(wrongCommitment));
    }
    
    @Test
    public void testGetAllTerminalsWhenNone() throws IOException {
    	List<Terminal> terminals = accessor.getAllTerminals();
    	
    	assertNotNull(terminals);
    	assertEquals(0, terminals.size());
    }
    
    @Test
    public void testGetAllTerminalsWhenOne() throws IOException {
    	Terminal t = saveTerminal();
    	List<Terminal> terminals = accessor.getAllTerminals();
    	
    	assertNotNull(terminals);
    	assertEquals(1, terminals.size());
    	assertEquals(t.getId(), terminals.get(0).getId());
    }
    
    @Test
    public void testGetAllTerminalsWhenTwo() throws IOException {
    	saveTerminal("1");
    	saveTerminal("2");
    	List<Terminal> terminals = accessor.getAllTerminals();
    	
    	assertNotNull(terminals);
    	assertEquals(2, terminals.size());
    	assertFalse(terminals.get(0).getId() == terminals.get(1).getId());
    }
}
