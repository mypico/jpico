package org.mypico.jpico.test.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.crypto.AuthTokenFactory;
import org.mypico.jpico.crypto.CryptoFactory;
import org.mypico.jpico.crypto.ISigmaVerifier;
import org.mypico.jpico.crypto.NewSigmaProver;
import org.mypico.jpico.crypto.NewSigmaVerifier;
import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.crypto.ProtocolViolationException;
import org.mypico.jpico.crypto.ServiceSigmaProver;
import org.mypico.jpico.crypto.ServiceSigmaVerifier;
import org.mypico.jpico.crypto.SimpleAuthToken;
import org.mypico.jpico.crypto.NewSigmaProver.ProverAuthRejectedException;
import org.mypico.jpico.crypto.NewSigmaProver.VerifierAuthFailedException;
import org.mypico.jpico.crypto.messages.EncPicoAuthMessage;
import org.mypico.jpico.crypto.messages.EncServiceAuthMessage;
import org.mypico.jpico.crypto.messages.EncStatusMessage;
import org.mypico.jpico.crypto.messages.EncryptedMessage;
import org.mypico.jpico.crypto.messages.StartMessage;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.test.data.TestDataFactory;
import org.mypico.jpico.test.util.Corrupter;
import org.mypico.jpico.test.util.TestClientInterface;
import org.mypico.jpico.test.util.UsesCryptoTest;

import sun.security.ssl.Debug;

public class AuthenticationTest extends UsesCryptoTest {
	
    private KeyPair proverIdKeyPair;
    private KeyPair verifierIdKeyPair;

    @Before
    public void setUp() throws Exception {
		proverIdKeyPair = CryptoFactory.INSTANCE.ecKpg().genKeyPair();
		verifierIdKeyPair = CryptoFactory.INSTANCE.ecKpg().genKeyPair();
    }

    /**
     * Helper method that runs the corruption test with the specified things to corrupt. If nothing
     * is set to corrupt, then it check for pass too.
     * 
     * @param thingsToCorrupt
     */
    private void doCorruptionTest(ThingsToCorrupt thingsToCorrupt) {
        final NewSigmaVerifier verifier = new NewSigmaVerifier(
        		NewSigmaProver.VERSION_1_1,
        		verifierIdKeyPair,
        		1,
        		new TestClientInterface("test"),
        		false);
        final CorruptingVerifier corruptingVerifier =
        		new CorruptingVerifier(verifier, thingsToCorrupt);
        
        final byte[] verifierCommitment = 
        		KeyPairing.commitServicePublicKey(verifierIdKeyPair.getPublic());

        final NewSigmaProver prover = new NewSigmaProver(
        		NewSigmaProver.VERSION_1_1,
        		proverIdKeyPair,
        		null,
        		corruptingVerifier,
        		verifierCommitment,
        		null);
        try {
        	prover.prove();
        	if (!thingsToCorrupt.isEmpty()) {
        		fail("Expected authentication to fail due to corruption");
        	}
        } catch (ProtocolViolationException e) {
        	// Expected
        } catch (ProverAuthRejectedException e) {
			// Expected
		} catch (VerifierAuthFailedException e) {
			// Expected
		} catch (IOException e) {
			fail("Unexpected communication error");
		}
    }

    private void doCorruptionTest(ThingsToCorrupt.Item thingToCorrupt) {
        doCorruptionTest(new ThingsToCorrupt(thingToCorrupt));
    }
    
	@Test
	@Deprecated
    public void testServiceProverVerifier() throws Exception {
    	// Make verifier
		final KeyPair verifierKp = CryptoFactory.INSTANCE.ecKpg().generateKeyPair();
    	final ServiceSigmaVerifier.Client client = new ServiceSigmaVerifier.Client() {
			
			@Override
			public AuthToken onAuthenticate(PublicKey proverPublicKey) {
				return new SimpleAuthToken("hello world");
			}
		};
    	final ISigmaVerifier verifier = new ServiceSigmaVerifier(verifierKp, client, false);
    	
    	// Data objects
    	final DataFactory factory = new TestDataFactory();
    	
    	final Service service = new Service(
    			factory,
    			"service name",
    			new URI("http://example.com"),
    			KeyPairing.commitServicePublicKey(verifierKp.getPublic()));
    	
		final KeyPair pairingKp = CryptoFactory.INSTANCE.ecKpg().generateKeyPair();
    	final KeyPairing pairing = new KeyPairing(factory, "pairing name", service, pairingKp, "");
    	
    	final ServiceSigmaProver prover = new ServiceSigmaProver(pairing, verifier, factory);
    	prover.startSession();
    }

    @Test
    public void testProve() throws Exception {
        final boolean cont = false;
        final String tokenString = "test prove";
        final int sessionId = 1;
        final NewSigmaVerifier verifier = new NewSigmaVerifier(
        		NewSigmaProver.VERSION_1_1,
        		verifierIdKeyPair,
        		sessionId,
        		new TestClientInterface(tokenString),
        		cont);
        
        final byte[] verifierCommitment = 
        		KeyPairing.commitServicePublicKey(verifierIdKeyPair.getPublic());

        final NewSigmaProver prover = new NewSigmaProver(
        		NewSigmaProver.VERSION_1_1,
        		proverIdKeyPair,
        		null,
        		verifier,
        		verifierCommitment,
        		null);

        final boolean contResult = prover.prove();
        assertSame(cont, contResult);
        assertSame(sessionId, prover.getVerifierSessionId());
        assertTrue(Arrays.equals(
        		proverIdKeyPair.getPublic().getEncoded(),
        		verifier.getProverIdPubKey().getEncoded()));
        assertTrue(Arrays.equals(
        		prover.getSharedKey().getEncoded(),
        		verifier.getSharedKey().getEncoded()));
        assertEquals(
        		AuthTokenFactory.fromByteArray(prover.getReceivedExtraData()).getFull(),
        		tokenString);
    }

    @Test
    public void testCorruptPicoEphemeralPublicKey() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.PICO_EPHEMERAL_PUBLIC_KEY);
    }

    @Test
    public void testCorruptPicoNonce() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.PICO_NONCE);
    }

    @Test
    public void testCorruptServiceEphemeralPublicKey() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.SERVICE_EPHEMERAL_PUBLIC_KEY);
    }

    @Test
    public void testCorruptServiceNonce() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.SERVICE_NONCE);
    }

    @Test
    public void testCorruptEncServiceAuthMessage() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.ENC_SERVICE_AUTH_MESSAGE_DATA);
    }

    @Test
    public void testCorruptEncServiceAuthMessageIv() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.ENC_SERVICE_AUTH_MESSAGE_IV);
    }

    @Test
    public void testCorruptEncAuthMessage() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.ENC_PICO_AUTH_MESSAGE_DATA);
    }

    @Test
    public void testCorruptEncAuthMessageIv() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.ENC_PICO_AUTH_MESSAGE_IV);
    }

    @Test
    public void testCorruptEncStatusMessageData() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.ENC_STATUS_MESSAGE_DATA);
    }

    @Test
    public void testCorruptEncStatusMessageIv() throws Exception {
        doCorruptionTest(ThingsToCorrupt.Item.ENC_STATUS_MESSAGE_IV);
    }

    @Test
    public void testCorruptNothing() throws Exception {
        doCorruptionTest(new ThingsToCorrupt());
    }

    @Test
    public void testFuzzCorruptThings() throws Exception {
        SecureRandom r = new SecureRandom();
        boolean[] flags =
                new boolean[] {false, false, false, false, false, false,
                        false, false, false, false};

        for (int i = 0; i < 40; i++) {
            for (int j = 0; j < flags.length; j++) {
                flags[j] = r.nextBoolean();
            }
            ThingsToCorrupt ttc = new ThingsToCorrupt(flags);
            Debug.println("testFuzzCorruptThings", "Corrupting " + ttc.toString());
            doCorruptionTest(ttc);
        }
    }

    final class CorruptingVerifier implements ISigmaVerifier {

        private final ISigmaVerifier verifier;
        public final ThingsToCorrupt thingsToCorrupt;

        public final Field startMessagePicoEphemeralPublicKey;
        public final Field startMessagePicoNonce;
        public final Field encServiceAuthMessageServiceEphemeralPublicKey;
        public final Field encServiceAuthMessageServiceNonce;
        public final Field encryptedMessageEncryptedData;
        public final Field encryptedMessageIV;

        public CorruptingVerifier(ISigmaVerifier verifier, ThingsToCorrupt things) {
            this.verifier = verifier;
            this.thingsToCorrupt = things;
            
            try {
	        	startMessagePicoEphemeralPublicKey = 
	            		StartMessage.class.getDeclaredField("picoEphemeralPublicKey");
	            startMessagePicoNonce = 
	            		StartMessage.class.getDeclaredField("picoNonce");
	            encServiceAuthMessageServiceEphemeralPublicKey = 
	            		EncServiceAuthMessage.class.getDeclaredField("serviceEphemPublicKey");
	            encServiceAuthMessageServiceNonce =
	            		EncServiceAuthMessage.class.getDeclaredField("serviceNonce");
	            encryptedMessageEncryptedData =
	            		EncryptedMessage.class.getDeclaredField("encryptedData");
	            encryptedMessageIV =
	            		EncryptedMessage.class.getDeclaredField("iv");
            } catch (NoSuchFieldException e) {
            	throw new RuntimeException(e);
            }

            // Make fields we are going to corrupt accessible.
            if (this.thingsToCorrupt
                    .contains(ThingsToCorrupt.Item.PICO_EPHEMERAL_PUBLIC_KEY))
                startMessagePicoEphemeralPublicKey.setAccessible(true);

            if (this.thingsToCorrupt.contains(ThingsToCorrupt.Item.PICO_NONCE))
                startMessagePicoNonce.setAccessible(true);

            if (this.thingsToCorrupt
                    .contains(ThingsToCorrupt.Item.SERVICE_EPHEMERAL_PUBLIC_KEY))
                encServiceAuthMessageServiceEphemeralPublicKey
                        .setAccessible(true);

            if (this.thingsToCorrupt
                    .contains(ThingsToCorrupt.Item.SERVICE_NONCE))
                encServiceAuthMessageServiceNonce.setAccessible(true);

            if (this.thingsToCorrupt.containsAny(
                    ThingsToCorrupt.Item.ENC_SERVICE_AUTH_MESSAGE_DATA,
                    ThingsToCorrupt.Item.ENC_PICO_AUTH_MESSAGE_DATA,
                    ThingsToCorrupt.Item.ENC_STATUS_MESSAGE_DATA))
                encryptedMessageEncryptedData.setAccessible(true);

            if (this.thingsToCorrupt.containsAny(
                    ThingsToCorrupt.Item.ENC_SERVICE_AUTH_MESSAGE_IV,
                    ThingsToCorrupt.Item.ENC_PICO_AUTH_MESSAGE_IV,
                    ThingsToCorrupt.Item.ENC_STATUS_MESSAGE_IV))
                encryptedMessageIV.setAccessible(true);

        }

        @Override
        public EncServiceAuthMessage start(StartMessage startMessage)
                throws IOException, ProtocolViolationException {
            // Corrupt some bits of the outgoing request
            try {
                // Generate (randomly) a new valid public key that is corrupted by one bit.
                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.PICO_EPHEMERAL_PUBLIC_KEY)) {
                    this.startMessagePicoEphemeralPublicKey
                            .set(startMessage,
                                    Corrupter
                                            .corrupt((PublicKey) this.startMessagePicoEphemeralPublicKey
                                                    .get(startMessage)));
                }

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.PICO_NONCE)) {
                    this.startMessagePicoNonce.set(startMessage,
                            Corrupter.corrupt((Nonce) this.startMessagePicoNonce
                                    .get(startMessage)));
                }

                // Forward to interface
                EncServiceAuthMessage encServiceAuthMessage =
                        this.verifier.start(startMessage);

                // TODO: Should this failure be captured some other way?
                if (encServiceAuthMessage == null)
                    throw new IOException("Proxy Service returned null EncServiceAuthMessage");

                // Corrupt some bits of the incoming reply

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.SERVICE_EPHEMERAL_PUBLIC_KEY)) {
                    this.encServiceAuthMessageServiceEphemeralPublicKey
                            .set(encServiceAuthMessage,
                                    Corrupter
                                            .corrupt((PublicKey) this.encServiceAuthMessageServiceEphemeralPublicKey
                                                    .get(encServiceAuthMessage)));
                }

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.SERVICE_NONCE)) {
                    this.encServiceAuthMessageServiceNonce
                            .set(encServiceAuthMessage,
                                    Corrupter
                                            .corrupt((Nonce) this.encServiceAuthMessageServiceNonce
                                                    .get(encServiceAuthMessage)));
                }

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.ENC_SERVICE_AUTH_MESSAGE_DATA)) {
                    this.encryptedMessageEncryptedData.set(
                            encServiceAuthMessage,
                            Corrupter.corrupt((byte[]) this.encryptedMessageEncryptedData
                                    .get(encServiceAuthMessage)));
                }

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.ENC_SERVICE_AUTH_MESSAGE_IV)) {
                    this.encryptedMessageIV.set(encServiceAuthMessage,
                            Corrupter.corrupt((byte[]) this.encryptedMessageIV
                                    .get(encServiceAuthMessage)));
                }

                return encServiceAuthMessage;

            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }

        }

        @Override
        public EncStatusMessage authenticate(
                EncPicoAuthMessage encAuthMessage) throws IOException, ProtocolViolationException {
            // Corrupt some bits of the EncAuthMessage
            try {
                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.ENC_PICO_AUTH_MESSAGE_DATA)) {
                    this.encryptedMessageEncryptedData.set(encAuthMessage,
                            Corrupter.corrupt((byte[]) this.encryptedMessageEncryptedData
                                    .get(encAuthMessage)));
                }

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.ENC_PICO_AUTH_MESSAGE_IV)) {
                    this.encryptedMessageIV.set(encAuthMessage,
                            Corrupter.corrupt((byte[]) this.encryptedMessageIV
                                    .get(encAuthMessage)));
                }

                EncStatusMessage encStatusMessage = this.verifier.authenticate(encAuthMessage);

                // TODO: Should this failure be captured some other way?
                //if (encStatusMessage == null)
                //    throw new IOException("Proxy Service returned null EncSessionDelegationMessage");

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.ENC_STATUS_MESSAGE_DATA)) {
                    this.encryptedMessageEncryptedData.set(
                            encStatusMessage,
                            Corrupter.corrupt((byte[]) this.encryptedMessageEncryptedData
                                    .get(encStatusMessage)));
                }

                if (this.thingsToCorrupt
                        .contains(ThingsToCorrupt.Item.ENC_STATUS_MESSAGE_IV)) {
                    this.encryptedMessageIV.set(encStatusMessage,
                            Corrupter.corrupt((byte[]) this.encryptedMessageIV
                                    .get(encStatusMessage)));
                }

                return encStatusMessage;
            } catch (IllegalArgumentException e) {
                throw new RuntimeException(e);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }

        }

    }

    static final class ThingsToCorrupt implements Set<ThingsToCorrupt.Item> {

        public enum Item {
            PICO_EPHEMERAL_PUBLIC_KEY,
            PICO_NONCE,
            SERVICE_EPHEMERAL_PUBLIC_KEY,
            SERVICE_NONCE,
            ENC_SERVICE_AUTH_MESSAGE_DATA,
            ENC_SERVICE_AUTH_MESSAGE_IV,
            ENC_PICO_AUTH_MESSAGE_DATA,
            ENC_PICO_AUTH_MESSAGE_IV,
            ENC_STATUS_MESSAGE_DATA,
            ENC_STATUS_MESSAGE_IV;

        };

        public final EnumSet<Item> items = EnumSet.noneOf(Item.class);

        /**
         * Creates an empty ThingsToCorrupt.
         */
        public ThingsToCorrupt() {}

        /**
         * Creates a ThingsToCorrupt from an array of items.
         * 
         * @param items to be corrupted.
         */
        public ThingsToCorrupt(Item... items) {
            for (Item item : items) {
                this.items.add(item);
            }
        }

        /**
         * Creates a ThingsToCorrupt from an array of items.
         * 
         * @param things boolean flags to be corrupted.
         */
        public ThingsToCorrupt(boolean... things) {
            Item[] allItems = Item.values();
            if (things.length != allItems.length) {
                throw new IllegalArgumentException(String.format(
                        "Array of Flags of things to corrupt should "
                                + "contain exactly %d items", allItems.length));
            }
            for (int i = 0; i < things.length; i++) {
                if (things[i])
                    this.items.add(allItems[i]);
            }
        }

        @Override
        public String toString() {
            return this.items.toString();
        }

        @Override
        public boolean contains(Object o) {
            return this.items.contains(o);
        }

        @Override
        public boolean containsAll(Collection<?> c) {
            return this.items.containsAll(c);
        }

        @Override
        public boolean isEmpty() {
            return this.items.isEmpty();
        }

        @Override
        public Iterator<Item> iterator() {
            return this.items.iterator();
        }

        @Override
        public int size() {
            return this.items.size();
        }

        @Override
        public Object[] toArray() {
            return this.items.toArray();
        }

        @Override
        public <T> T[] toArray(T[] a) {
            return this.items.toArray(a);
        }

        // A new containsAny method (has a slightly different signature to containsAll)

        public boolean containsAny(Item... items) {
            if (items.length == 0)
                return false;
            EnumSet<Item> set2 = EnumSet.copyOf(Arrays.asList(items));
            if (set2.size() < items.length) {
                Debug.println("AuthenticationTest.ThingsToCorrupt",
                        "Duplicate items handed to containsAny");
            }
            set2.retainAll(this);
            return (set2.size() > 0);
        }

        // The set is wrapped to make it immutable, so lots of unsupported operations.

        @Override
        public boolean add(Item e) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean addAll(Collection<? extends Item> c) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void clear() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean remove(Object o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean removeAll(Collection<?> c) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean retainAll(Collection<?> c) {
            throw new UnsupportedOperationException();
        }

    }
}
