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

/**
 * During continuous authentication messages are sent periodically between the prover and verifier.
 * Each message contains a state that indicates to the other side whether the continuous
 * authentication should continue, pause, stop. etc.
 * <p>
 * This enum defines the possible states that the continous authentication can be in.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public enum ReauthState {
    CONTINUE,
    PAUSE,
    STOP,
    ERROR;

    /**
     * Exception thrown if the enum is out of range.
     */
    @SuppressWarnings("serial")
    public static class InvalidReauthStateIndexException extends Exception {
        public InvalidReauthStateIndexException(byte state) {
            super(String.format("State %d does not exist. Valid states between 0 and %d", state,
                ReauthState.values().length - 1));
        }
    }

    /**
     * Convert from a byte (which will be the value extracted from a message) to the typed
     * enum value.
     *
     * @param reauthStateIndex The index into the enum (as sent in a message, say).
     * @return the enum state the index corresponds to.
     * @throws InvalidReauthStateIndexException in case the index is out of range.
     */
    public static ReauthState fromByte(byte reauthStateIndex)
        throws InvalidReauthStateIndexException {
        if (reauthStateIndex < 0 || reauthStateIndex >= ReauthState.values().length)
            throw new InvalidReauthStateIndexException(reauthStateIndex);
        final ReauthState reauthState = ReauthState.values()[reauthStateIndex];
        return reauthState;
    }

    /**
     * Convert the enum value to a byte (index), for inclusion in a message.
     *
     * @return the integer index the <code>ReauthState</code> corresponds to.
     */
    public byte toByte() {
        return (byte) ordinal();
    }
}
