package org.mypico.jpico.test.gson;

import static org.junit.Assert.assertEquals;

import java.security.PublicKey;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.gson.ByteArrayGsonSerializer;
import org.mypico.jpico.gson.PublicKeyGsonSerializer;
import org.mypico.jpico.test.util.UsesCryptoTest;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class PublicKeyGsonSerializerTest extends UsesCryptoTest {

    private static Gson gson;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        // Set up Gson instance with the right adapter registered
        gson = new GsonBuilder()
                .registerTypeAdapter(byte[].class, new ByteArrayGsonSerializer())
                .registerTypeAdapter(PublicKey.class, new PublicKeyGsonSerializer())
                .disableHtmlEscaping()
                .create();
    }

    private static PublicKey key;

    @Before
    public void setUp() throws Exception {
		key = CryptoFactory.INSTANCE.ecKpg().generateKeyPair().getPublic();
    }

    @Test
    public void testSame() throws Exception {
        String json1 = gson.toJson(key, PublicKey.class);
        String json2 = gson.toJson(key, PublicKey.class);
        assertEquals(json1, json2);
    }

    @Test
    public void testCycle() throws Exception {
        String json = gson.toJson(key, PublicKey.class);
        assertEquals(key, gson.fromJson(json, PublicKey.class));
    }
	
	@Test
    public void testDeserialiseGoodKey() {
		String jsonKey = "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEW7kvO6naieWNCD2WsAB61ZxNWa0D8zodn1ao35Pm+mSA0X/VvkSFOUti9TdZk9W/";
		
		
		
	}
	
	@Test
	public void testDeserialiseBadKey() {
		String[] jsonKeys = {
				null,
				"",
				"hello1234"
		};
		
	}
    
}
