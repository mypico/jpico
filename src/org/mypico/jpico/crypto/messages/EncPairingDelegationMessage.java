package org.mypico.jpico.crypto.messages;

import java.io.IOException;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.crypto.AuthTokenFactory;
import org.mypico.jpico.crypto.util.LengthPrependedDataInputStream;

/**
 * Encrypted form of the {@link PairingDelegationMessage}.
 * <p>
 * Encrypted pairing delegation message. Used for delegating a pairing from one Pico to another.
 * <p>
 * <p>An <code>EncPairingDelegationMessage</code> contains several cleartext items:
 * <ul>
 * <li><code>sessionId</code></li>
 * <li><code>sequenceNumber</code></li>
 * <li><code>serviceName</code></li>
 * <li><code>token</code></li>
 * <li><code>commitment</code></li>
 * <li><code>address</code></li>
 * <li><code>extraData</code></li>
 * </ul>
 * <p>
 * <p>The encrypted items are encrypted using an AES cipher in Gallois counter mode, using the Pico's
 * symmetric session encryption key. The format of encrypted items is as follows:
 * <p>
 * <p><code>l||signature||m||mac</code>
 * <p>
 * <p>Where:
 * <ul>
 * <li><code>l</code> and <code>m</code> are four-byte (big-endian) integers specifying the length
 * (in bytes) of the next item.</li>
 * <li><code>signature</code> and <code>mac</code> are items of the corresponding unencrypted
 * {@link PairingDelegationMessage}.</li>
 * </ul>
 *
 * @author David Llewellyn-Jonew &lt;David.Llewellyn-Jone@cl.cam.ac.uk&gt;
 * @see PairingDelegationMessage
 */
public final class EncPairingDelegationMessage extends
    EncryptedMessage<PairingDelegationMessage> {

    /**
     * Constructor.
     *
     * @param sessionId     The session id.
     * @param encryptedData The data to encrypt.
     * @param iv            The iv to use for encryption.
     */
    public EncPairingDelegationMessage(int sessionId, byte[] encryptedData, byte[] iv) {
        super(sessionId, encryptedData, iv);
    }

    @Override
    protected PairingDelegationMessage createUnencryptedMessage(
        LengthPrependedDataInputStream dis)
        throws IOException,
        org.mypico.jpico.crypto.messages.EncryptedMessage.FieldDeserializationException {
        final SequenceNumber sequenceNumber = SequenceNumber.fromByteArray(dis.readVariableLengthByteArray());
        final String serviceName = new String(dis.readVariableLengthByteArray());
        final AuthToken token = AuthTokenFactory.fromByteArray(dis.readVariableLengthByteArray());
        final byte[] commitment = dis.readVariableLengthByteArray();
        final String address = new String(dis.readVariableLengthByteArray());
        final byte[] extraData = dis.readVariableLengthByteArray();

        return new PairingDelegationMessage(sessionId, sequenceNumber, serviceName, token, commitment, address, extraData);
    }
}
