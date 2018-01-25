package org.mypico.jpico.test.gson;

import java.net.URI;

import org.mypico.jpico.test.data.service.ServiceTest;
import org.mypico.jpico.visualcode.KeyAuthenticationVisualCode;

public class KeyAuthenticationVisualCodeTest {

	public static KeyAuthenticationVisualCode getCode() {
		try {
            return KeyAuthenticationVisualCode.getInstance(
            		ServiceTest.ADDRESS,
            		ServiceTest.COMMITMENT, 
            		new URI("http://rendezvous.example.com/channel/example"),
            		"terminalCommitment".getBytes());
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured whilst creating visual code.", e);
        }
	}
}
