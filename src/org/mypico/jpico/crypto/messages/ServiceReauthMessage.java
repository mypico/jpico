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

import org.mypico.jpico.crypto.util.LengthPrependedDataOutputStream;

import com.google.common.base.Objects;

/**
 * The Service reauthentication message. This message is sent as part of the continuous
 * authentication process. It's sent periodically to demonstrate that the Service is still actively
 * authenticating to the Pico.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see PicoReauthMessage
 */
public final class ServiceReauthMessage extends
    UnencryptedMessage<EncServiceReauthMessage> {

    private final SequenceNumber sequenceNumber;
    private final int timeout;
    private final ReauthState reauthState;

    /**
     * Constructor.
     *
     * @param sessionId      The session id.
     * @param reauthState    The current reauthentication state (e.g. paused, stopped, etc.).
     * @param timeout        The time within which the Pico must respond with its own
     *                       {@link PicoReauthMessage}. If no valid response is received within this
     *                       time, the continuous authenication will be considered to have been
     *                       broken. This is measured in milliseconds.
     * @param sequenceNumber The sequence number, which should increase by one each message.
     */
    public ServiceReauthMessage(final int sessionId, final ReauthState reauthState,
                                final int timeout, final SequenceNumber sequenceNumber) {
        super(sessionId);
        this.reauthState = reauthState;
        this.timeout = timeout;
        this.sequenceNumber = sequenceNumber;
    }

    /* ************************** Accessor methods ************************** */

    /**
     * Get the sequence number. This must be incremented by one for each message, or the
     * Pico should consider the authenticated link to be broken.
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
     * Get the timeout value. The Pico must respond to the message within this time, or the
     * authenticated link will be considered to be broken.
     *
     * @return the timeout in milliseconds.
     */
    public int getTimeout() {
        return timeout;
    }

    /* *********************** Serialisation Methods *********************** */

    @Override
    protected EncServiceReauthMessage createEncryptedMessage(
        byte[] encryptedData, byte[] iv) {
        return new EncServiceReauthMessage(sessionId, encryptedData, iv);
    }

    @Override
    protected void writeDataToEncrypt(LengthPrependedDataOutputStream los) throws IOException {
        los.write(reauthState.toByte());
        los.writeInt(timeout);
        los.writeVariableLengthByteArray(sequenceNumber.toByteArray());
        los.flush();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof ServiceReauthMessage) {
            ServiceReauthMessage other = (ServiceReauthMessage) o;
            return sessionId == other.sessionId &&
                reauthState == other.reauthState &&
                timeout == other.timeout &&
                sequenceNumber.equals(other.sequenceNumber);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sessionId, reauthState, timeout, sequenceNumber);
    }
}
