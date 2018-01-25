package org.mypico.jpico.test.gson;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.BeforeClass;
import org.junit.Test;
import org.mypico.jpico.comms.org.apache.commons.codec.binary.Base64;
import org.mypico.jpico.gson.VisualCodeGson;
import org.mypico.jpico.test.util.UsesCryptoTest;
import org.mypico.jpico.test.visualcode.DelegatePairingVisualCodeTest;
import org.mypico.jpico.test.visualcode.KeyPairingVisualCodeTest;
import org.mypico.jpico.test.visualcode.LensAuthenticationVisualCodeTest;
import org.mypico.jpico.test.visualcode.LensPairingVisualCodeTest;
import org.mypico.jpico.visualcode.DelegatePairingVisualCode;
import org.mypico.jpico.visualcode.KeyAuthenticationVisualCode;
import org.mypico.jpico.visualcode.KeyPairingVisualCode;
import org.mypico.jpico.visualcode.LensAuthenticationVisualCode;
import org.mypico.jpico.visualcode.LensPairingVisualCode;
import org.mypico.jpico.visualcode.SignedVisualCode;
import org.mypico.jpico.visualcode.VisualCode;

import com.google.gson.Gson;

public class VisualCodeGsonTest extends UsesCryptoTest {

    private static Gson GSON;
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    	GSON = VisualCodeGson.gson;
    }

    // Lens auth visual code

    @Test
    public void testLensAuthenticationSerialize() throws Exception {
        String json = GSON.toJson(LensAuthenticationVisualCodeTest.getCode());
        assertNotNull(json);
        assertTrue(json.length() > 0);
    }

    @Test
    public void testLensAuthenticationSame() throws Exception {
        LensAuthenticationVisualCode vc = LensAuthenticationVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(vc);
        assertEquals(json1, json2);
    }

    @Test
    public void testLensAuthenticationCycle() throws Exception {
        LensAuthenticationVisualCode vc = LensAuthenticationVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(GSON.fromJson(GSON.toJson(vc), VisualCode.class));
        assertEquals(json1, json2);
    }

    // Lens pairing visual code

    // - Some credentials

    @Test
    public void testLensPairingSomeSerialize() throws Exception {
        String json = GSON.toJson(LensPairingVisualCodeTest.getCodeSome());
        assertNotNull(json);
    }

    @Test
    public void testLensPairingSomeSame() throws Exception {
        LensPairingVisualCode vc = LensPairingVisualCodeTest.getCodeSome();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(vc);
        assertEquals(json1, json2);
    }

    @Test
    public void testLensPairingSomeCycle() throws Exception {
        LensPairingVisualCode vc = LensPairingVisualCodeTest.getCodeSome();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(GSON.fromJson(GSON.toJson(vc), VisualCode.class));
        assertEquals(json1, json2);
    }

    // - No credentials

    @Test
    public void testLensPairingNoSerialize() throws Exception {
        String json = GSON.toJson(LensPairingVisualCodeTest.getCodeNone());
        assertNotNull(json);
    }

    @Test
    public void testLensAuthenticationNoSame() throws Exception {
        LensPairingVisualCode vc = LensPairingVisualCodeTest.getCodeNone();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(vc);
        assertEquals(json1, json2);
    }

    @Test
    public void testLensAuthenticationNoCycle() throws Exception {
        LensPairingVisualCode vc = LensPairingVisualCodeTest.getCodeNone();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(GSON.fromJson(GSON.toJson(vc), VisualCode.class));
        assertEquals(json1, json2);
    }

    // Key auth visual code

    @Test
    public void testKeyAuthenticationSerialize() throws Exception {
        String json = GSON.toJson(KeyAuthenticationVisualCodeTest.getCode());
        assertNotNull(json);
    }

    @Test
    public void testKeyAuthenticationSame() throws Exception {
        KeyAuthenticationVisualCode vc = KeyAuthenticationVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(vc);
        assertEquals(json1, json2);
    }

    @Test
    public void testKeyAuthenticationCycle() throws Exception {
        KeyAuthenticationVisualCode vc = KeyAuthenticationVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(GSON.fromJson(GSON.toJson(vc), VisualCode.class));
        assertEquals(json1, json2);
    }

    // Key pairing visual code

    @Test
    public void testKeyPairingSerialize() throws Exception {
        String json = GSON.toJson(KeyPairingVisualCodeTest.getCode());
        assertNotNull(json);
    }

    @Test
    public void testKeyPairingSame() throws Exception {
        SignedVisualCode vc = KeyPairingVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(vc);
        assertEquals(json1, json2);
    }

    @Test
    public void testKeyPairingCycle() throws Exception {
        SignedVisualCode vc = KeyPairingVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(GSON.fromJson(GSON.toJson(vc), VisualCode.class));
        assertEquals(json1, json2);
    }

    // Delegate pairing visual code

    @Test
    public void testDelegatePairingSerialize() throws Exception {
        String json = GSON.toJson(DelegatePairingVisualCodeTest.getCode());
        assertNotNull(json);
    }

    @Test
    public void testDelegatePairingSame() throws Exception {
    	DelegatePairingVisualCode vc = DelegatePairingVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(vc);
        assertEquals(json1, json2);
    }

    @Test
    public void testDelegatePairingCycle() throws Exception {
    	DelegatePairingVisualCode vc = DelegatePairingVisualCodeTest.getCode();
        String json1 = GSON.toJson(vc);
        String json2 = GSON.toJson(GSON.fromJson(GSON.toJson(vc), VisualCode.class));
        assertEquals(json1, json2);
    }
    
	
	/* TEST CORRECT CODE DESERIALISATION */
	
	static final String VALID_KEY_AUTH_CODE =
			"{\"td\":{},\"sc\":\"n0LypRzb2YaL4XEXuJfXGdW/vGzVrRRJP5xpPAc8wVA=\",\"ed\":\"\",\"sa\":\"http://rendezvous.mypico.org/channel/1f52fceed07b488e84416151026cc241\",\"t\":\"KA\"}";
	
	/**
	 * Test that having deserialised a Key Auth code, the fields have the correct values.
	 */
	@Test
	public void testKeyAuthCode() {
		final String json = VALID_KEY_AUTH_CODE;
		KeyAuthenticationVisualCode code = (KeyAuthenticationVisualCode) GSON.fromJson(json, VisualCode.class);
		assertTrue("A valid KeyAuthCode JSON string fails isValid", code.isValid());
		
		byte[] commitment = code.getServiceCommitment();
		byte[] extraData = code.getExtraData();
		
		String b64commitment = "n0LypRzb2YaL4XEXuJfXGdW/vGzVrRRJP5xpPAc8wVA=";
		String b64extra = "";
		
		assertEquals(b64commitment, Base64.encodeBase64String(commitment));
		assertEquals(b64extra, Base64.encodeBase64String(extraData));
	}
	
	static final String VALID_KEY_PAIRING_CODE =
			"{\"sig\":\"MDUCGBdMimt7aOOty1UGxyZL2aYs1wu2uNjdUgIZAJE1AoTnmxpKMTsk18GBGrq4K8uRFCWK7Q==\",\"td\":{},\"spk\":\"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEW7kvO6naieWNCD2WsAB61ZxNWa0D8zodn1ao35Pm+mSA0X/VvkSFOUti9TdZk9W/\",\"ed\":\"\",\"sn\":\"PicoServerTest\",\"sa\":\"http://rendezvous.mypico.org/channel/e06fd69444e1403d8e7aef58abcf9be9\",\"t\":\"KP\"}";
	
	/**
	 * Test that having deserialised a Key Pairing code, the fields have the correct values.
	 */
	@Test
	public void testKeyPairingCode() {
		final String json = VALID_KEY_PAIRING_CODE;
		KeyPairingVisualCode code = (KeyPairingVisualCode) GSON.fromJson(json, VisualCode.class);
		assertTrue("A valid KeyPairingCode JSON string fails isValid", code.isValid());
		
		String name = code.getServiceName();
		byte[] pk = code.getServicePublicKey().getEncoded();
		byte[] sig = code.getSignature();
		
		String name2 = "PicoServerTest";
		String b64sig = "MDUCGBdMimt7aOOty1UGxyZL2aYs1wu2uNjdUgIZAJE1AoTnmxpKMTsk18GBGrq4K8uRFCWK7Q==";
		String b64pk = "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEW7kvO6naieWNCD2WsAB61ZxNWa0D8zodn1ao35Pm+mSA0X/VvkSFOUti9TdZk9W/";
		
		assertEquals(name, name2);
		assertEquals(b64sig, Base64.encodeBase64String(sig));
		assertEquals(b64pk, Base64.encodeBase64String(pk));
		
	}
	
	static final String VALID_LENS_AUTHENTICATION_CODE =
			"{\"t\":\"LA\",\"td\":{\"ta\":\"http://rendezvous.mypico.org/channel/b6696e1b1eee4574b42e6ca3300730e1\",\"tc\":\"6NkF0Fcj11/nr1uEParTNxSp0E7XyGeVIgMDkOaztRE=\"}}";
	
	/**
	 * Test that having deserialised a Lens Authentication code, the fields have the correct values.
	 */
	@Test
	public void testLensAuthenticationCode() {
		final String json = VALID_LENS_AUTHENTICATION_CODE;
		LensAuthenticationVisualCode code = (LensAuthenticationVisualCode) GSON.fromJson(json, VisualCode.class);
		assertTrue("A valid LensAuthenticationCode JSON string fails isValid", code.isValid());
		
		String ta = code.getTerminalAddress().toString();
		byte[] tc = code.getTerminalCommitment();
		String type = code.getType();
		
		String xta = "http://rendezvous.mypico.org/channel/b6696e1b1eee4574b42e6ca3300730e1";
		String xtc = "6NkF0Fcj11/nr1uEParTNxSp0E7XyGeVIgMDkOaztRE=";
		String xtype = "LA";
		
		assertEquals(xtype, type);
		assertEquals(xta, ta);
		assertEquals(xtc, Base64.encodeBase64String(tc));
	}
	
	static final String VALID_LENS_PAIRING_CODE =
			"{\"t\":\"LP\",\"sc\":\"MO7Fdp/wUoTyqAfSDwtl/xXMhdIq7Q2GncMfUvH0t+w=\",\"td\":{\"ta\":\"http://rendezvous.mypico.org/channel/43629418bb70438da95c07f03af15be1\",\"tc\":\"R8On9zclAqwHNwnzrEi2JmRZrtBw3gb3PZU/O+X7aQc=\"}}";
	
	/**
	 * Test that having deserialised a Lens Pairing code, the fields have the correct values.
	 */
	@Test
	public void testLensPairingCode() {
		final String json = VALID_LENS_PAIRING_CODE;
		LensPairingVisualCode code = (LensPairingVisualCode) GSON.fromJson(json, VisualCode.class);
		assertTrue("A valid LensPairingCode JSON string fails isValid", code.isValid());
		
		String ta = code.getTerminalAddress().toString();
		byte[] tc = code.getTerminalCommitment();
		byte[] sc = code.getServiceCommitment();
		
		String xta = "http://rendezvous.mypico.org/channel/43629418bb70438da95c07f03af15be1";
		String xtc = "R8On9zclAqwHNwnzrEi2JmRZrtBw3gb3PZU/O+X7aQc=";
		String xsc = "MO7Fdp/wUoTyqAfSDwtl/xXMhdIq7Q2GncMfUvH0t+w=";
		
		assertEquals(xta, ta);
		assertEquals(xtc, Base64.encodeBase64String(tc));
		assertEquals(xsc, Base64.encodeBase64String(sc));
	}
	
	/**
	 * Test bad codes. Deserialising any one of these should cause an exception.
	 */
	@Test
	public void testBadJsonCodes() {
		String[] badJson = {
				////// evil key auth codes
				// Grayam's evil code (malicious RVP)
				"{\"td\":{},\"sc\":\"n0LypRzb2YaL4XEXuJfXGdW/vGzVrRRJP5xpPAc8wVA=\",\"ed\":\"\",\"sa\":\"http://rendezvous.mypico.org/channel/1f52fceed07b488e84416151026cc241\"}\",\"t\":\"KA\"}",
				// with empty strings
				"{\"td\":{},\"sc\":\"\",\"ed\":\"\",\"sa\":\"\",\"t\":\"KA\"}",
				// with random parameters
				"{\"td\":{},\"sc\":\"asijgh\",\"ed\":\"asgujh\",\"sa\":\"aisyvtn\",\"t\":\"KA\"}",
				// with missing parameters
				"{\"td\":{},\"sc\":\"asijgh\",\"ed\":\"asgujh\",\"sa\":\"aisyvtn\"}",
				"{\"sc\":\"asijgh\",\"ed\":\"asgujh\",\"sa\":\"aisyvtn\",\"t\":\"KA\"}",
				"{\"td\":{},\"ed\":\"asgujh\",\"sa\":\"aisyvtn\",\"t\":\"KA\"}",
				"{\"td\":{},\"sc\":\"asijgh\",\"sa\":\"aisyvtn\",\"t\":\"KA\"}",
				"{\"td\":{},\"sc\":\"asijgh\",\"ed\":\"asgujh\",\"t\":\"KA\"}",
				// with swapped primitives and objects
				"{\"td\":\"\",\"sc\":{},\"ed\":{},\"sa\":{},\"t\":\"KA\"}",
				
				////// evil key pairing codes
				// invalid sig
				"{\"sig\":\"awkvhasilhbnaslkjg!£$%^&*\",\"td\":{},\"spk\":\"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEW7kvO6naieWNCD2WsAB61ZxNWa0D8zodn1ao35Pm+mSA0X/VvkSFOUti9TdZk9W/\",\"ed\":\"\",\"sn\":\"PicoServerTest\",\"sa\":\"http://rendezvous.mypico.org/channel/e06fd69444e1403d8e7aef58abcf9be9\",\"t\":\"KP\"}",
				// invalid public key
				"{\"sig\":\"awkvhasilhbnaslkjg!£$%^&*\",\"td\":{},\"spk\":\"sthhnsachhnfdlsk!£^£$&$%&\",\"ed\":\"\",\"sn\":\"PicoServerTest\",\"sa\":\"http://rendezvous.mypico.org/channel/e06fd69444e1403d8e7aef58abcf9be9\",\"t\":\"KP\"}",
				// with empty strings
				"{\"sig\":\"\",\"td\":{},\"spk\":\"\",\"ed\":\"\",\"sn\":\"\",\"sa\":\"\",\"t\":\"KP\"}",
				// with missing parameters
				"{\"td\":{},\"spk\":\"\",\"ed\":\"\",\"sn\":\"\",\"sa\":\"\",\"t\":\"KP\"}",
				"{\"sig\":\"\",\"spk\":\"\",\"ed\":\"\",\"sn\":\"\",\"sa\":\"\",\"t\":\"KP\"}",
				"{\"sig\":\"\",\"td\":{},\"ed\":\"\",\"sn\":\"\",\"sa\":\"\",\"t\":\"KP\"}",
				"{\"sig\":\"\",\"td\":{},\"spk\":\"\",\"sn\":\"\",\"sa\":\"\",\"t\":\"KP\"}",
				"{\"sig\":\"\",\"td\":{},\"spk\":\"\",\"ed\":\"\",\"sa\":\"\",\"t\":\"KP\"}",
				"{\"sig\":\"\",\"td\":{},\"spk\":\"\",\"ed\":\"\",\"sn\":\"\",\"t\":\"KP\"}",
				"{\"sig\":\"\",\"td\":{},\"spk\":\"\",\"ed\":\"\",\"sn\":\"\",\"sa\":\"\"}",
				// with swapped primitives and objects
				"{\"sig\":{},\"td\":\"\",\"spk\":{},\"ed\":{},\"sn\":{},\"sa\":{},\"t\":\"KP\"}",
				
				// todo: add cases for malformed codes of other types
		};
		
		for (String json : badJson) {
			try {
				VisualCode code = GSON.fromJson(json, VisualCode.class);
				// if it didn't throw an exception, the code should be invalid
				assertFalse("An invalid JSON string generated a valid code!\nThe string was \"" + json + "\"", code.isValid());
			} catch (Exception e) {
				// exceptions are good and expected here!
			}
		}
		
	}
	
}
