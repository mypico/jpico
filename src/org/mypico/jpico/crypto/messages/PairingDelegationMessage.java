package org.mypico.jpico.crypto.messages;

import java.io.IOException;
import java.util.Arrays;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.crypto.util.LengthPrependedDataOutputStream;

import com.google.common.base.Objects;

/**
 * This message is sent from one Pico to another in order to delegate a pairing. In practice, it
 * is a session cookie that's delegated. The message is sent in the extraData field of the
 * SIGMA-I protocol.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 */
public final class PairingDelegationMessage extends
    UnencryptedMessage<EncPairingDelegationMessage> {

    private final SequenceNumber sequenceNumber;
    private final String serviceName;
    private final AuthToken token;

    private final byte[] commitment;
    private final String address;

    private final byte[] extraData;

    /**
     * Constructor.
     *
     * @param sessionId      The session id.
     * @param sequenceNumber The sequence number of the message.
     * @param serviceName    The service name to delegate.
     * @param token          The auth token (cookie) for delegation.
     * @param commitment     The service commitment.
     * @param address        The address of the service of delegation.
     * @param extraData      An additional data to be sent encrypted with the message.
     */
    public PairingDelegationMessage(final int sessionId,
                                    final SequenceNumber sequenceNumber,
                                    final String serviceName,
                                    final AuthToken token,
                                    final byte[] commitment,
                                    final String address,
                                    final byte[] extraData) {
        super(sessionId);

        this.sequenceNumber = sequenceNumber;
        this.serviceName = serviceName;
        this.token = token;
        this.commitment = commitment;
        this.address = address;
        this.extraData = extraData;
    }

	/* ************************** Accessor methods ************************** */

    /**
     * Get the sequence number.
     *
     * @return the sequence number.
     */
    public SequenceNumber getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Get the service name.
     *
     * @return the service name.
     */
    public String getServiceName() {
        return serviceName;
    }

    /**
     * Get the auth token.
     *
     * @return the auth token.
     */
    public AuthToken getAuthToken() {
        return token;
    }

    /**
     * Get the service commitment.
     *
     * @return the service commitment.
     */
    public byte[] getCommitment() {
        return commitment;
    }

    /**
     * Get the service address.
     *
     * @return the service address.
     */
    public String getAddress() {
        return address;
    }

    /**
     * Get the extra data from the message.
     *
     * @return the extra data.
     */
    public byte[] getExtraData() {
        return extraData;
    }

    /* *********************** Serialisation Methods *********************** */
    @Override
    protected EncPairingDelegationMessage createEncryptedMessage(
        final byte[] encryptedData, final byte[] iv) {
        return new EncPairingDelegationMessage(sessionId, encryptedData, iv);
    }

    @Override
    protected void writeDataToEncrypt(final LengthPrependedDataOutputStream los)
        throws IOException {
        los.writeVariableLengthByteArray(sequenceNumber.toByteArray());
        los.writeVariableLengthByteArray(serviceName.getBytes());
        los.writeVariableLengthByteArray(token.toByteArray());
        los.writeVariableLengthByteArray(commitment);
        los.writeVariableLengthByteArray(address.toString().getBytes());
        los.writeVariableLengthByteArray(extraData);
        los.flush();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof PairingDelegationMessage) {
            PairingDelegationMessage other = (PairingDelegationMessage) o;
            return sessionId == other.sessionId
                && sequenceNumber.equals(other.sequenceNumber)
                && serviceName.equals(other.serviceName)
                && token.equals(other.token)
                && Arrays.equals(commitment, other.commitment)
                && address.equals(other.address)
                && Arrays.equals(extraData, other.extraData);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sessionId, sequenceNumber, serviceName, token,
            commitment, address, extraData);
    }

}
