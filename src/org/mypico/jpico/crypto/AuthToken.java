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


package org.mypico.jpico.crypto;

import java.io.IOException;

/**
 * An AuthToken must provide a {@link #getFull() getFull} method which returns the full form of the
 * token to be transferred automatically to the terminal and a {@link #getFallback() getFallback}
 * method which returns a string to be displayed to the user when no communication channel between
 * the Pico and user's terminal is available.
 * <p>
 * <p>
 * An AuthToken is sent from the service to the Pico in the final message of the Pico authentication
 * protocol.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see SessionDelegationMessage
 */
public interface AuthToken {
    /**
     * Get the full auth token.
     *
     * @return the full form of the token to be transferred automatically to the terminal
     */
    public abstract String getFull();

    /**
     * Get a string to be displayed to the user when no communication channel between
     * the Pico and user's terminal is available.
     *
     * @return the string to display.
     */
    public abstract String getFallback();

    /**
     * Returns the <code>AuthToken</code> as a byte array.
     *
     * @return the <code>AuthToken</code> as a byte array.
     * @throws IOException thown if an error occurs convertying to a byte array.
     */
    public abstract byte[] toByteArray() throws IOException;
}
