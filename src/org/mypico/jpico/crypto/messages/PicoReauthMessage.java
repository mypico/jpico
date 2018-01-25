/*
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * This file is part of jpico.
 *
 * jpico is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * jpico is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with jpico. If not, see
 * <http://www.gnu.org/licenses/>.
 */


package org.mypico.jpico.crypto.messages;

import java.io.IOException;
import java.util.Arrays;

import org.mypico.jpico.crypto.util.LengthPrependedDataOutputStream;

import com.google.common.base.Objects;

/**
 * The Pico reauthentication message. This message is sent as part of the continuous authentication
 * process. It's sent periodically to demonstrate that the Pico is still actively authenticating
 * to the service.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see ServiceReauthMessage
 */
public final class PicoReauthMessage extends
    UnencryptedMessage<EncPicoReauthMessage> {

    private final SequenceNumber sequenceNumber;
    private final ReauthState reauthState;
    private final byte[] extraData;

    /**
     * Constructor.
     *
     * @param sessionId      The session id.
     * @param reauthState    The current reauthentication state (e.g. paused, stopped, etc.).
     * @param sequenceNumber The sequence number, which should increase by one each message.
     */
    public PicoReauthMessage(final int sessionId, final ReauthState reauthState,
                             final SequenceNumber sequenceNumber) {
        this(sessionId, reauthState, sequenceNumber, new byte[0]);
    }

    /**
     * Constructor.
     *
     * @param sessionId      The session id.
     * @param reauthState    The current reauthentication state (e.g. paused, stopped, etc.).
     * @param sequenceNumber The sequence number, which should increase by one each message.
     * @param extraData      Any extra data that will be sent encrypted with the message.
     */
    public PicoReauthMessage(final int sessionId, final ReauthState reauthState,
                             final SequenceNumber sequenceNumber, final byte[] extraData) {
        super(sessionId);
        this.reauthState = reauthState;
        this.sequenceNumber = sequenceNumber;
        this.extraData = extraData;
    }

    /* ************************** Accessor methods ************************** */

    /**
     * Get the sequence number. This must be incremented by one for each message, or the
     * service should consider the authenticated link to be broken.
     *
     * @return the sequence number.
     */
    public SequenceNumber getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Get the reauth state (e.g. paused, stopped, etc.).
     *
     * @return the reauth state.
     */
    public ReauthState getReauthState() {
        return reauthState;
    }

    /**
     * Get the extra data sent encrypted with the message.
     *
     * @return the extra data.
     */
    public byte[] getExtraData() {
        return extraData;
    }
    
    /* *********************** Serialisation Methods *********************** */

    @Override
    protected EncPicoReauthMessage createEncryptedMessage(
        final byte[] encryptedData, final byte[] iv) {
        return new EncPicoReauthMessage(sessionId, encryptedData, iv);
    }

    @Override
    protected void writeDataToEncrypt(final LengthPrependedDataOutputStream los)
        throws IOException {
        los.write(reauthState.toByte());
        los.writeVariableLengthByteArray(sequenceNumber.toByteArray());
        los.writeVariableLengthByteArray(extraData);
        los.flush();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof PicoReauthMessage) {
            PicoReauthMessage other = (PicoReauthMessage) o;
            return sessionId == other.sessionId &&
                reauthState == other.reauthState &&
                sequenceNumber.equals(other.sequenceNumber) &&
                Arrays.equals(extraData, other.extraData);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sessionId, reauthState, sequenceNumber, extraData);
    }
}