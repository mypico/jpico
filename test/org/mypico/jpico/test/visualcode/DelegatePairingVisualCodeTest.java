package org.mypico.jpico.test.visualcode;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.test.data.service.ServiceTest;
import org.mypico.jpico.visualcode.DelegatePairingVisualCode;

public class DelegatePairingVisualCodeTest {
	public static final Map<String, String> NO_CREDENTIALS = new HashMap<String, String>();
	public static final Map<String, String> SOME_CREDENTIALS;
	
	static {
		SOME_CREDENTIALS = new HashMap<String, String>();
		SOME_CREDENTIALS.put("key1", "value1");
		SOME_CREDENTIALS.put("key2", "value2");
	}
	
	public static DelegatePairingVisualCode getCode() {
        try {
            return DelegatePairingVisualCode.getInstance(
            		ServiceTest.NAME,
            		Nonce.getRandomInstance(),
            		new URI("http://rendezvous.example.com/channel/example"),
            		CryptoFactory.INSTANCE.ecKpg().generateKeyPair().getPublic());
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured whilst creating visual code.", e);
        }
    }
}
