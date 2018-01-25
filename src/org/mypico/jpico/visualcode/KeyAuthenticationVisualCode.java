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

import org.mypico.jpico.Preconditions;

/**
 * VisualCode containing details to authenticate with a service.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public class KeyAuthenticationVisualCode extends KeyVisualCode {

    protected static final int COMMITMENT_LENGTH = 32;

    public static String TYPE = "KA";

    /**
     * Generate an instance of a {@link KeyAuthenticationVisualCode} from the data provided.
     *
     * @param serviceAddress     The address of the servie to add to the code.
     * @param serviceCommitment  The service commitment to add to the code.
     * @param terminalAddress    Ther address of the terminal to add to the code.
     * @param terminalCommitment Ther terminal commitment to add to the code.
     * @return a {@link KeyAuthenticationVisualCode} instance.
     */
    public static KeyAuthenticationVisualCode getInstance(
        final URI serviceAddress,
        final byte[] serviceCommitment,
        final URI terminalAddress,
        final byte[] terminalCommitment) {
        return getInstance(serviceAddress, serviceCommitment, terminalAddress, terminalCommitment, null);
    }

    /**
     * Generate an instance of a {@link KeyAuthenticationVisualCode} from the data provided.
     *
     * @param serviceAddress     The address of the servie to add to the code.
     * @param serviceCommitment  The service commitment to add to the code.
     * @param terminalAddress    Ther address of the terminal to add to the code.
     * @param terminalCommitment Ther terminal commitment to add to the code.
     * @param extraData          Any extra data to include in the code.
     * @return a {@link KeyAuthenticationVisualCode} instance.
     */
    public static KeyAuthenticationVisualCode getInstance(
        final URI serviceAddress,
        final byte[] serviceCommitment,
        final URI terminalAddress,
        final byte[] terminalCommitment,
        final byte[] extraData) {
        final KeyAuthenticationVisualCode code = new KeyAuthenticationVisualCode();
        code.serviceAddress = Preconditions.checkNotNullOrEmpty(
            serviceAddress, "serviceAddress cannot be null or empty");
        code.serviceCommitment = Preconditions.checkNotNullOrEmpty(
            serviceCommitment, "serviceCommitment cannot be null or empty");
        code.extraData = extraData;
        code.terminal = TerminalDetails.getInstance(terminalAddress, terminalCommitment);
        return code;
    }

    /**
     * Generate an instance of a {@link KeyAuthenticationVisualCode} from the data provided,
     * without including information about a terminal.
     *
     * @param serviceAddress    The address of the servie to add to the code.
     * @param serviceCommitment The service commitment to add to the code.
     * @return a {@link KeyAuthenticationVisualCode} instance with no terminal info included.
     */
    public static KeyAuthenticationVisualCode getInstanceNoTerminal(final URI serviceAddress,
                                                                    final byte[] serviceCommitment) {
        return getInstanceNoTerminal(serviceAddress, serviceCommitment, null);
    }

    /**
     * Generate an instance of a {@link KeyAuthenticationVisualCode} from the data provided,
     * without including information about a terminal.
     *
     * @param serviceAddress    The address of the servie to add to the code.
     * @param serviceCommitment The service commitment to add to the code.
     * @param extraData         Any extra data to include in the code.
     * @return a {@link KeyAuthenticationVisualCode} instance with no terminal info included.
     */
    public static KeyAuthenticationVisualCode getInstanceNoTerminal(
        final URI serviceAddress,
        final byte[] serviceCommitment,
        final byte[] extraData) {
        final KeyAuthenticationVisualCode code = new KeyAuthenticationVisualCode();
        code.serviceAddress = Preconditions.checkNotNullOrEmpty(
            serviceAddress, "serviceAddress cannot be null or empty");
        code.serviceCommitment = Preconditions.checkNotNullOrEmpty(
            serviceCommitment, "serviceCommitment cannot be null or empty");
        code.terminal = TerminalDetails.getEmptyInstance();
        code.extraData = extraData;
        return code;
    }

    @SerializedName("sc")
    private byte[] serviceCommitment;
    @SerializedName("ed")
    private byte[] extraData;

    /**
     * Default constructor.
     */
    protected KeyAuthenticationVisualCode() {
        super(TYPE);
    }

    /**
     * Get the service commitment from the code.
     *
     * @return the service commitment.
     */
    public byte[] getServiceCommitment() {
        return serviceCommitment;
    }

    /**
     * Get the extra data from the code.
     *
     * @return the extra data.
     */
    public byte[] getExtraData() {
        return extraData;
    }

    @Override
    public boolean isValid() {
        return super.isValid() &&
            serviceCommitment != null &&
            serviceCommitment.length == COMMITMENT_LENGTH &&
            extraData != null;
    }

}
