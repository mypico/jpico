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
import java.security.PublicKey;

import org.mypico.jpico.Preconditions;
import org.mypico.jpico.crypto.HashUtils;
import org.mypico.jpico.crypto.Nonce;

/**
 * A class representing a visual code used for pairing with a terminal.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 * @see VisualCode
 * @see org.mypico.jpico.data.terminal.Terminal
 * @see TerminalDetails
 */
public class TerminalPairingVisualCode extends VisualCode
    implements WithTerminalDetails {

    public static String TYPE = "TP";

    @SerializedName("tn")
    private String terminalName;
    @SerializedName("n")
    private Nonce nonce;
    @SerializedName("td")
    private TerminalDetails terminal;

    /**
     * Default constructor.
     */
    protected TerminalPairingVisualCode() {
        super(TYPE);
    }

    /**
     * Get an instance of the {@link TerminalPairingVisualCode} containing the data provided.
     *
     * @param terminalName      The terminal name to add to the code.
     * @param nonce             The nonce to include in the code.
     * @param terminalAddress   The address of ther terminal to include in the code.
     * @param terminalPublicKey The long term public key of the terminal to include in the code.
     * @return a {@link TerminalPairingVisualCode} instance.
     */
    public static TerminalPairingVisualCode getInstance(
        String terminalName,
        Nonce nonce,
        URI terminalAddress,
        PublicKey terminalPublicKey) {
        TerminalPairingVisualCode code = new TerminalPairingVisualCode();
        code.terminalName = Preconditions.checkNotNullOrEmpty(
            terminalName, "terminalName cannot be null or empty");
        code.nonce = checkNotNull(nonce, "nonce cannot be null");
        code.terminal = TerminalDetails.getInstance(
            terminalAddress, HashUtils.sha256Key(terminalPublicKey));
        return code;
    }

    /**
     * Get the terminal name from the code.
     *
     * @return the terminal name.
     */
    public String getTerminalName() {
        return terminalName;
    }

    /**
     * Get the nonce from the code.
     *
     * @return the nonce.
     */
    public Nonce getNonce() {
        return nonce;
    }

    @Override
    public byte[] getTerminalCommitment() {
        return terminal.getTerminalCommitment();
    }

    @Override
    public URI getTerminalAddress() {
        return terminal.getTerminalAddress();
    }

    @Override
    public boolean hasTerminal() {
        return (terminal != null && terminal.hasTerminal());
    }

    /**
     * Check whether the details of the code are valid. For the code to be valid, none of the
     * data items (terminal name, nonce, terminal address, terminal public key) can be null.
     *
     * @return true if the code has all the valid data required, false o/w.
     */
    public boolean isValid() {
        return super.isValid() &&
            terminalName != null &&
            nonce != null &&
            terminal != null;
    }

}
