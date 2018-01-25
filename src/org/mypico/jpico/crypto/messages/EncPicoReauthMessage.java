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

import org.mypico.jpico.crypto.messages.ReauthState.InvalidReauthStateIndexException;
import org.mypico.jpico.crypto.util.LengthPrependedDataInputStream;

/**
 * Encrypted form of the {@link PicoReauthMessage}.
 * <p>
 * Encrypted Pico reauth message. Used to re authenticate a Pico during continuous authentication.
 * <p>
 * <p>An <code>EncPicoReauthMessage</code> contains several cleartext items:
 * <ul>
 * <li><code>sessionId</code></li>
 * <li><code>reauthState</code></li>
 * <li><code>sequenceNumber</code></li>
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
 * {@link PicoReauthMessage}.</li>
 * </ul>
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @see PicoReauthMessage
 */
public final class EncPicoReauthMessage extends
    EncryptedMessage<PicoReauthMessage> {

    /**
     * Constructor.
     *
     * @param sessionId     The session id.
     * @param encryptedData The data to encrypt.
     * @param iv            The iv to use for encryption.
     */
    public EncPicoReauthMessage(int sessionId, byte[] encryptedData, byte[] iv) {
        super(sessionId, encryptedData, iv);
    }

    @Override
    protected PicoReauthMessage createUnencryptedMessage(
        final LengthPrependedDataInputStream dis) throws IOException {
        final ReauthState reauthState;
        try {
            reauthState = ReauthState.fromByte(dis.readByte());
        } catch (InvalidReauthStateIndexException e) {
            throw new IOException(e);
        }
        final SequenceNumber sequenceNumber =
            SequenceNumber.fromByteArray(dis.readVariableLengthByteArray());
        final byte[] extraData = dis.readVariableLengthByteArray();
        return new PicoReauthMessage(sessionId, reauthState, sequenceNumber, extraData);
    }
}