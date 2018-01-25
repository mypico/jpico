package org.mypico.jpico.test.gson;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.gson.ByteArrayGsonSerializer;
import org.mypico.jpico.gson.NonceGsonSerializer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class NonceGsonTest {

    private static Gson gson;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        // Set up Gson instance with the right adapter registered
        gson = new GsonBuilder()
                .registerTypeAdapter(byte[].class, new ByteArrayGsonSerializer())
                .registerTypeAdapter(Nonce.class, new NonceGsonSerializer())
                .disableHtmlEscaping()
                .create();
    }

    private static Nonce nonce;

    @Before
    public void setUp() throws Exception {
        nonce = Nonce.getRandomInstance();
    }

    @Test
    public void testSame() throws Exception {
        String json1 = gson.toJson(nonce, Nonce.class);
        String json2 = gson.toJson(nonce, Nonce.class);
        assertEquals(json1, json2);
    }

    @Test
    public void testCycle() throws Exception {
        String json = gson.toJson(nonce, Nonce.class);
        assertEquals(nonce, gson.fromJson(json, Nonce.class));
    }
}
