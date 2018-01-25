package org.mypico.jpico.test.crypto.messages;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.Test;
import org.mypico.jpico.crypto.messages.SequenceNumber;
import org.mypico.jpico.test.util.Corrupter;

public class SequenceNumberTest {

    /**
     * Test the wrap-around behaviour of the sequenceNumber
     * 
     * @throws Exception
     */
    @Test
    public void wrapAroundTest() throws Exception {

        Field f = SequenceNumber.class.getDeclaredField("SEQUENCE_NUMBER_LENGTH");
        f.setAccessible(true);
        int size = f.getInt(SequenceNumber.class);

        wrapAroundTest(size, false);
        wrapAroundTest(size, true);

    }

    private void wrapAroundTest(int size, boolean send) {
        byte[] x = new byte[size];
        Arrays.fill(x, (byte) -1);
        x[size - 1] = (byte) -10;

        SequenceNumber c = SequenceNumber.fromByteArray(x); // Previous Challenge
        SequenceNumber c2 = c.getResponse(); // Current challenge
        for (int count = x[size - 1] + 1; count < -x[size - 1]; count++) {
            if (send)
                c2 = simulateSend(c2);
            assertTrue(c.verifyResponse(c2));

            c = c2;
            c2 = c2.getResponse();
            if (send)
                c = simulateSend(c);
            byte[] b = c.toByteArray();

            if (count >= 0) {
                assertTrue(b[b.length - 1] == count);
                for (int byteIndex = 0; byteIndex < b.length - 1; byteIndex++) {
                    assertEquals(b[byteIndex], 0);
                }
            }
            System.out.print("[ ");
            for (int byteIndex = 0; byteIndex < b.length; byteIndex++) {
                System.out.print(b[byteIndex] + " ");
            }
            System.out.println("]");
        }
    }

    @Test
    public void randomSequenceNumberTestWithNetwork() {
        SequenceNumber c = SequenceNumber.getRandomInstance();

        for (int i = 0; i < 600; i++) {
            SequenceNumber previous = c;
            SequenceNumber response = c.getResponse();
            c = simulateSend(response);
            assertTrue("Response failed to verify \n" +
                    "   Previous: " + previous.toString() + "\n" +
                    "   Response: " + response.toString() + "\n" +
                    "   Network:  " + c.toString(), previous.verifyResponse(c));
        }
    }

    @Test
    public void sequenceNumberCorruptTest() {
        SequenceNumber c = SequenceNumber.getRandomInstance();
        SequenceNumber previous = c;
        c = simulateSend(c).getResponse();

        byte[] responseSent = c.toByteArray();
        Corrupter.corruptOneBitInPlace(responseSent);
        c = SequenceNumber.fromByteArray(responseSent);

        assertFalse(previous.verifyResponse(c));

    }


    /* Serialise and de-serialise, to simulate sending. */
    private SequenceNumber simulateSend(SequenceNumber c) {
        return SequenceNumber.fromByteArray(c.toByteArray());
    }
}
