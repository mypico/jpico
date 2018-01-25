package org.mypico.jpico.test.visualcode;

import java.net.URI;

import org.mypico.jpico.visualcode.LensAuthenticationVisualCode;

public class LensAuthenticationVisualCodeTest {
	
	public static LensAuthenticationVisualCode getCode() {
        try {
            return LensAuthenticationVisualCode.getInstance(
            		new URI("http://rendezvous.example.com/channel/example"),
            		"terminalCommitment".getBytes());
        } catch (Exception e) {
            throw new RuntimeException(
                    "Exception occured whilst creating visual code.", e);
        }
    }
}
