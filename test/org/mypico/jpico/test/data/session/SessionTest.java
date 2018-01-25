package org.mypico.jpico.test.data.session;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.crypto.SimpleAuthToken;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImpFactory;
import org.mypico.jpico.test.data.TestDataFactory;
import org.mypico.jpico.test.data.pairing.PairingTest;
import org.mypico.jpico.test.util.UsesCryptoTest;

public class SessionTest extends UsesCryptoTest {

    public static final DataFactory DATA_FACTORY = new TestDataFactory();
    public static final SessionImpFactory FACTORY = DATA_FACTORY;
    public static final String REMOTE_ID = "session remote ID";
    public static final SecretKey SECRET_KEY = new SecretKeySpec("secret".getBytes(), "AES");
    public static final Pairing PAIRING = PairingTest.getPairing();
    public static final AuthToken AUTH_TOKEN = new SimpleAuthToken("auth");

    @Test
    public void testSessionSessionImpFactorySession() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testNewInstanceActive() {
        Session s = Session.newInstanceActive(
                FACTORY, REMOTE_ID, SECRET_KEY, PAIRING, AUTH_TOKEN);
        assertNotNull(s);
    }

    @Test
    public void testNewInstanceClosed() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testNewInstanceInError() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testEqualsObject() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testSetStatus() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testSetError() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testSetLastAuthDate() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testHasAuthToken() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testGetAuthToken() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testCheckRemoteIdNull() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testCheckRemoteIdEmpty() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testCheckLastAuthDateNull() {
    	//TODO fail("Not yet implemented");
    }

    @Test
    public void testCheckLastAuthDateFuture() {
    	//TODO fail("Not yet implemented");
    }
}
