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

import com.google.common.base.Objects;

import java.io.IOException;
import java.util.Arrays;

import org.mypico.jpico.crypto.util.LengthPrependedDataOutputStream;

/**
 * The last message of the SIGMA-I protocol, which is sent from the service to the Pico.
 * <p>
 * A <code>StatusMessage</code> contains three items:
 * <ul>
 * <li><code>sessionId</code> - The id for this session, to allow message sequences to be matched.
 * <li><code>status</code> - Specifies the result of the authentication.</li>
 * <li><code>extraData</code> - Any optional extra data sent encrypted from the service to
 * the Pico.</li>
 * </ul>
 * <p>
 * The next message in the protocol is the {@link PicoReauthMessage}, sent only if continuous
 * authentication is requested.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public final class StatusMessage extends UnencryptedMessage<EncStatusMessage> {

    public static final byte OK_DONE = (byte) 0;
    public static final byte OK_CONTINUE = (byte) 1;
    public static final byte REJECTED = (byte) -1;

    /**
     * Get an instance of the message that specifies the authentication failed.
     *
     * @param sessionId The session id of the message exchange.
     * @return a new instance of the message.
     */
    public static StatusMessage getRejectInstance(int sessionId) {
        return new StatusMessage(sessionId, REJECTED, null);
    }

    /**
     * Get an instance of the message that specifies the authentication succeeded and no continuous
     * authentication is requested.
     *
     * @param sessionId The session id of the message exchange.
     * @return a new instance of the message.
     */
    public static StatusMessage getDoneInstance(int sessionId, byte[] extraData) {
        return new StatusMessage(sessionId, OK_DONE, extraData);
    }

    /**
     * Get an instance of the message that specifies the authentication succeeded and continuous
     * authentication is requested.
     *
     * @param sessionId The session id of the message exchange.
     * @return a new instance of the message.
     */
    public static StatusMessage getContinueInstance(int sessionId, byte[] extraData) {
        return new StatusMessage(sessionId, OK_CONTINUE, extraData);
    }

    private final byte status;
    private final byte[] extraData;

    /**
     * Constructor.
     *
     * @param sessionId The session id.
     * @param status    The authentication state (e.g. success, rejected, continue, etc.).
     * @param extraData Any extra data that will be sent encrypted with the message.
     */
    StatusMessage(int sessionId, byte status, byte[] extraData) {
        super(sessionId);
        this.status = status;
        if (extraData == null) {
            this.extraData = new byte[0];
        } else {
            this.extraData = extraData;
        }
    }

    /**
     * Get the authentication status.
     *
     * @return the authentication status.
     */
    public byte getStatus() {
        return status;
    }

    /**
     * Get the extra data sent encrypted with the message.
     *
     * @return the extra data.
     */
    public byte[] getExtraData() {
        return extraData;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof StatusMessage) {
            StatusMessage other = (StatusMessage) obj;
            return (status == other.status) && Arrays.equals(extraData, other.extraData);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sessionId, status, extraData);
    }

    @Override
    protected EncStatusMessage createEncryptedMessage(byte[] encryptedData, byte[] iv) {
        return new EncStatusMessage(sessionId, encryptedData, iv);
    }

    @Override
    protected void writeDataToEncrypt(LengthPrependedDataOutputStream los) throws IOException {
        los.writeByte(status);
        los.writeVariableLengthByteArray(extraData);
        los.flush();
    }

}
