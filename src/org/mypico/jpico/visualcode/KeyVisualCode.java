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

import com.google.gson.annotations.SerializedName;

import java.net.URI;

/**
 * Abstract class representing a VisualCode containing a key.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public abstract class KeyVisualCode extends VisualCode implements WithTerminalDetails {

    @SerializedName("sa")
    protected URI serviceAddress;
    @SerializedName("td")
    protected TerminalDetails terminal;

    /**
     * Constructor.
     *
     * @param type The type of visual code.
     */
    protected KeyVisualCode(final String type) {
        super(type);
    }

    /**
     * Get the service address for the code.
     *
     * @return the service address.
     */
    public URI getServiceAddress() {
        return serviceAddress;
    }

    @Override
    public URI getTerminalAddress() {
        return terminal.getTerminalAddress();
    }

    @Override
    public byte[] getTerminalCommitment() {
        return terminal.getTerminalCommitment();
    }

    @Override
    public boolean hasTerminal() {
        return (terminal != null && terminal.hasTerminal());
    }

    @Override
    public boolean isValid() {
        return super.isValid() &&
            serviceAddress != null &&
            serviceAddress.toString().length() > 0 &&
            terminal != null;
    }

}
