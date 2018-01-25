package org.mypico.jpico.test.gson;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mypico.jpico.gson.ByteArrayGsonSerializer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class ByteArrayGsonSerializerTest {

    private static Gson gson;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        // Set up Gson instance with the right adapter registered
        gson = new GsonBuilder().registerTypeAdapter(
                byte[].class, new ByteArrayGsonSerializer()).create();
    }

    private static byte[] bytes;

    @Before
    public void setUp() throws Exception {
        bytes = "some bytes".getBytes();
    }

    @Test
    public void testSame() throws Exception {
        String json1 = gson.toJson(bytes, byte[].class);
        String json2 = gson.toJson(bytes, byte[].class);
        assertEquals(json1, json2);
    }

    @Test
    public void testCycle() throws Exception {
        String json = gson.toJson(bytes, byte[].class);
        assertTrue(Arrays.equals(bytes, gson.fromJson(json, byte[].class)));
    }
}
