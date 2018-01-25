package org.mypico.jpico.test.data.terminal;

import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.data.terminal.Terminal;


public class TerminalTest {

	public static String name(String mod) {
		return "terminal name" + mod;
	}
	
	public static byte[] commitment(String mod) {
		return ("terminal commitment" + mod).getBytes();
	}
	
	public static final String DEFAULT_NAME = name("");
	public static final byte[] DEFAULT_COMMITMENT = commitment("");

	public static Terminal getTerminal(Terminal.ImpFactory factory, String mod) {
        try {
            return new Terminal(
            		factory,
            		name(mod),
            		commitment(mod),
            		CryptoFactory.INSTANCE.ecKpg().generateKeyPair());
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured while creating Terminal instance", e);
        }
    }
}
