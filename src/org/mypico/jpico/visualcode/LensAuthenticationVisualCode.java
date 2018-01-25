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

import java.net.URI;

import com.google.gson.annotations.SerializedName;


/**
 * Pico lens visual code for authentication.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public class LensAuthenticationVisualCode extends LensVisualCode {

    public static String TYPE = "LA";

    /**
     * Get an instance of a {@link LensAuthenticationVisualCode}.
     *
     * @param terminalAddress    The terminal address to include in the code.
     * @param terminalCommitment The terminal commitment to include in the code.
     * @return a {@link LensAuthenticationVisualCode} instance.
     */
    public static LensAuthenticationVisualCode getInstance(
        URI terminalAddress,
        byte[] terminalCommitment) {
        final LensAuthenticationVisualCode code = new LensAuthenticationVisualCode();
        code.terminal = TerminalDetails.getInstance(terminalAddress, terminalCommitment);
        return code;
    }

    /**
     * Get an instance of a {@link LensAuthenticationVisualCode} that doesn't contain any
     * terminal information.
     *
     * @return a {@link LensAuthenticationVisualCode} instance without any terminal details
     * included.
     */
    public static LensAuthenticationVisualCode getInstanceNoTerminal() {
        final LensAuthenticationVisualCode code = new LensAuthenticationVisualCode();
        code.terminal = TerminalDetails.getEmptyInstance();
        return code;
    }

    // no-arg constructor for Gson
    protected LensAuthenticationVisualCode() {
        super(TYPE);
    }


    @Override
    public boolean isValid() {
        return super.isValid();
    }

}
