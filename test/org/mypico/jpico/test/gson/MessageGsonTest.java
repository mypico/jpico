package org.mypico.jpico.test.gson;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.crypto.messages.EncPicoAuthMessage;
import org.mypico.jpico.crypto.messages.EncServiceAuthMessage;
import org.mypico.jpico.crypto.messages.PicoAuthMessage;
import org.mypico.jpico.crypto.messages.ServiceAuthMessage;
import org.mypico.jpico.crypto.messages.StartMessage;
import org.mypico.jpico.gson.MessageGson;
import org.mypico.jpico.test.util.UsesCryptoTest;

import com.google.gson.Gson;

/*
 * This class contains test cases for the MessageGson class which provides a custom Gson object for
 * doing JSON serialization of SIGMA protocol messages.
 * 
 * There are separate for message components like PublicKey instances and also whole Message
 * classes. For each, there is test to ensure two serializations of the same object yield the same
 * result (test...Same) and a test to ensure that for any object obj:
 * obj.equals(deserialize(serialize(obj))) is true (test...Cycle)
 */
public class MessageGsonTest extends UsesCryptoTest {

    private static KeyGenerator encKg;
    private static KeyGenerator macKg;
    private static Gson gson;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        encKg = KeyGenerator.getInstance("AES", "BC");
        encKg.init(256);
        macKg = KeyGenerator.getInstance("HMACSHA256", "BC");

        gson = MessageGson.gson;
    }

    // Helper methods for getting the test Message instances.

    private static StartMessage getStartMessage() {
        return StartMessage.getInstance(
                (byte) 1,
				CryptoFactory.INSTANCE.ecKpg().generateKeyPair().getPublic(),
                Nonce.getRandomInstance()
                );
    }

    private static ServiceAuthMessage getServiceAuthMessage()
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException {
        return ServiceAuthMessage.getInstance(
				0, CryptoFactory.INSTANCE.ecKpg().generateKeyPair().getPublic(),
				Nonce.getRandomInstance(),
				Nonce.getRandomInstance(), CryptoFactory.INSTANCE.ecKpg().generateKeyPair(),
                macKg.generateKey()
                );
    }

    private static EncServiceAuthMessage getEncServiceAuthMessage()
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException,
            NoSuchPaddingException, IOException {
        return getServiceAuthMessage().encrypt(encKg.generateKey());
    }

    private static PicoAuthMessage getAuthMessage()
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException {
        return PicoAuthMessage.getInstance(
                0, Nonce.getRandomInstance(),
				CryptoFactory.INSTANCE.ecKpg().generateKeyPair().getPublic(),
				CryptoFactory.INSTANCE.ecKpg().generateKeyPair(),
                macKg.generateKey(),
                "some extra data".getBytes()
                );
    }

    private static EncPicoAuthMessage getEncAuthMessage()
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException,
            NoSuchPaddingException, IOException {
        return getAuthMessage().encrypt(encKg.generateKey());
    }

    // TESTS

    // StartMessage

    @Test
    public void testStartMessageSame() throws Exception {
        StartMessage msg = getStartMessage();
        String json1 = gson.toJson(msg, StartMessage.class);
        String json2 = gson.toJson(msg, StartMessage.class);
        assertEquals(json1, json2);
    }

    @Test
    public void testStartMessageCycle() throws Exception {
        StartMessage msg = getStartMessage();
        String json = gson.toJson(msg, StartMessage.class);
        assertEquals(msg, gson.fromJson(json, StartMessage.class));
    }

    // ServiceAuthMessage

    @Test
    public void testServiceAuthMessageSame() throws Exception {
        ServiceAuthMessage msg = getServiceAuthMessage();
        String json1 = gson.toJson(msg, ServiceAuthMessage.class);
        String json2 = gson.toJson(msg, ServiceAuthMessage.class);
        assertEquals(json1, json2);
    }

    @Test
    public void testServiceAuthMessageCycle() throws Exception {
        ServiceAuthMessage msg = getServiceAuthMessage();
        String json = gson.toJson(msg, ServiceAuthMessage.class);
        assertEquals(msg, gson.fromJson(json, ServiceAuthMessage.class));
    }

    // EncServiceAuthMessage

    @Test
    public void testEncServiceAuthMessageSame() throws Exception {
        EncServiceAuthMessage msg = getEncServiceAuthMessage();
        String json1 = gson.toJson(msg, EncServiceAuthMessage.class);
        String json2 = gson.toJson(msg, EncServiceAuthMessage.class);
        assertEquals(json1, json2);
    }

    @Test
    public void testEncServiceAuthMessageCycle() throws Exception {
        EncServiceAuthMessage msg = getEncServiceAuthMessage();
        String json = gson.toJson(msg, EncServiceAuthMessage.class);
        assertEquals(msg, gson.fromJson(json, EncServiceAuthMessage.class));
    }

    // AuthMessage

    @Test
    public void testAuthMessageSame() throws Exception {
        PicoAuthMessage msg = getAuthMessage();
        String json1 = gson.toJson(msg, PicoAuthMessage.class);
        String json2 = gson.toJson(msg, PicoAuthMessage.class);
        assertEquals(json1, json2);
    }

    @Test
    public void testAuthMessageCycle() throws Exception {
        PicoAuthMessage msg = getAuthMessage();
        String json = gson.toJson(msg, PicoAuthMessage.class);
        assertEquals(msg, gson.fromJson(json, PicoAuthMessage.class));
    }

    // EncAuthMessage

    @Test
    public void testEncAuthMessageSame() throws Exception {
        EncPicoAuthMessage msg = getEncAuthMessage();
        String json1 = gson.toJson(msg, EncPicoAuthMessage.class);
        String json2 = gson.toJson(msg, EncPicoAuthMessage.class);
        assertEquals(json1, json2);
    }

    @Test
    public void testEncAuthMessageCycle() throws Exception {
        EncPicoAuthMessage msg = getEncAuthMessage();
        String json = gson.toJson(msg, EncPicoAuthMessage.class);
        assertEquals(msg, gson.fromJson(json, EncPicoAuthMessage.class));
    }
}
