package org.mypico.jpico.test.util;

import java.security.PublicKey;

import org.mypico.jpico.crypto.IContinuousVerifier;
import org.mypico.jpico.crypto.ISigmaVerifier;
import org.mypico.jpico.crypto.SimpleAuthToken;

public class TestClientInterface implements ISigmaVerifier.Client,
        IContinuousVerifier.Client {
	
	private final String tokenString;
	
	public TestClientInterface(String tokenString) {
		this.tokenString = tokenString;
	}
	
	public String getTokenString() {
		return tokenString;
	}

    @Override
    public void onPause(PublicKey picoPublicKey) {}

    @Override
    public void onStop(PublicKey picoPublicKey) {}

    @Override
    public void onResume(PublicKey picoPublicKey) {}

    @Override
    public ClientAuthorisation onAuthenticate(PublicKey picoPublicKey, byte[] extraData) {
	    return ClientAuthorisation.accept(new SimpleAuthToken(tokenString).toByteArray());
    }

}
