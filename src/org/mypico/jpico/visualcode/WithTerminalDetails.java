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


package org.mypico.jpico.visualcode;

import org.mypico.jpico.data.terminal.Terminal;

import java.net.URI;

/**
 * Interface of a {@link VisualCode} which may include the details of a terminal for session
 * delegation.
 *
 * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
 */
public interface WithTerminalDetails {

    /**
     * @return the address of the terminal, or <code>null</code> if terminal details
     * are not present.
     */
    URI getTerminalAddress();

    /**
     * Return the terminal's commitment, which is the hash of its public key (see
     * {@link Terminal#getCommitment()}).
     *
     * @return the commitment of the terminal, or <code>null</code> if terminal details
     * are not present.
     */
    byte[] getTerminalCommitment();

    /**
     * Check whether this visual code includes the terminal details or not. Session delegation is
     * not necessary for some applications and in these cases no terminal details are included in
     * any visual code.
     *
     * @return <code>true</code> if the terminal address and commitment are present and
     * <code>false</code> otherwise.
     */
    boolean hasTerminal();
}
