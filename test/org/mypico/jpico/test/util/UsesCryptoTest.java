package org.mypico.jpico.test.util;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class UsesCryptoTest {
	
	static {
		ensureBouncyCastleProvider();
	}

	public static void ensureBouncyCastleProvider() {
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
    }
}
