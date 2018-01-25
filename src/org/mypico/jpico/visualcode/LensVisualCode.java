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
 * Abstract base class for visual codes used by the Pico Lens.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public abstract class LensVisualCode extends VisualCode implements WithTerminalDetails {

    // For subclasses with no-arg constructors to call.
    protected LensVisualCode(String type) {
        super(type);
    }

    @SerializedName("td")
    protected TerminalDetails terminal;

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
            hasTerminal();
    }

}
