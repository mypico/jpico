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

import static com.google.common.base.Preconditions.checkNotNull;

import java.net.URI;
import java.util.Map;

import org.mypico.jpico.Preconditions;

/**
 * Pico lens visual code for pairing. Contains the rendezvous channel to get
 * the credentials.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public class LensPairingVisualCode extends LensVisualCode implements WithTerminalDetails {

    public static String TYPE = "LP";

    protected static final int COMMITMENT_LENGTH = 32;

    @SerializedName("sc")
    protected byte[] serviceCommitment;

    /**
     * Get an instance of a {@link LensPairingVisualCode}.
     *
     * @param serviceCommitment  The service commitment to inlude in the code.
     * @param terminalAddress    The terminal address to include in the code.
     * @param terminalCommitment The terminal commitment to include in the code.
     * @return the {@link LensPairingVisualCode} instance.
     */
    public static LensPairingVisualCode getInstance(
        byte[] serviceCommitment,
        URI terminalAddress,
        byte[] terminalCommitment) {
        final LensPairingVisualCode code = new LensPairingVisualCode();
        code.serviceCommitment = Preconditions.checkNotNullOrEmpty(
            serviceCommitment, "serviceCommitment cannot be null");
        code.terminal = TerminalDetails.getInstance(terminalAddress, terminalCommitment);
        return code;
    }

    // no-arg constructor for Gson
    protected LensPairingVisualCode() {
        super(TYPE);
    }

    /**
     * Get the service commitment for the code.
     *
     * @return the service commitment.
     */
    public byte[] getServiceCommitment() {
        return serviceCommitment;
    }

    @Override
    public boolean isValid() {
        return super.isValid() &&
            serviceCommitment != null &&
            serviceCommitment.length == COMMITMENT_LENGTH;
    }

}
