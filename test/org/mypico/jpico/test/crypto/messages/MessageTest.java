package org.mypico.jpico.test.crypto.messages;

import javax.crypto.KeyGenerator;

import org.junit.BeforeClass;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.test.util.UsesCryptoTest;

public class MessageTest extends UsesCryptoTest {

    protected static KeyGenerator macKg;
    protected static KeyGenerator encKg;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        // Set up some more key generators for symmetric keys
        //encKg = KeyGenerator.getInstance("AES", "BC");
        //encKg.init(256);
        encKg = CryptoFactory.INSTANCE.aes256Kg();
        //macKg = KeyGenerator.getInstance("HMACSHA256", "BC");
        macKg = CryptoFactory.INSTANCE.sha256HmacKg();
    }

    public MessageTest() {
        super();
    }
}
