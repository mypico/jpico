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
 * Implementation of the {@link WithTerminalDetails} interface of a {@link VisualCode} which may
 * include the details of a terminal for session delegation.
 *
 * @see WithTerminalDetails
 */
final class TerminalDetails implements WithTerminalDetails {

    /**
     * Get an instance of the {@link TerminalDetails} class.
     *
     * @param address    The terminal address to include in the code.
     * @param commitment The terminal commitment to include in the code.
     * @return a {@link TerminalDetails} instance.
     */
    static TerminalDetails getInstance(URI address, byte[] commitment) {
        final TerminalDetails details = new TerminalDetails();
        details.address = Preconditions.checkNotNullOrEmpty(
            address, "address cannot be null or empty");
        details.commitment = Preconditions.checkNotNullOrEmpty(
            commitment, "commitment cannot be null or empty");
        return details;
    }

    /**
     * Get an empty instance of the {@link TerminalDetails} class, which contains no explicit
     * details about a particular terminal.
     *
     * @return a {@link TerminalDetails} instance.
     */
    static TerminalDetails getEmptyInstance() {
        return new TerminalDetails();
    }

    @SerializedName("ta")
    private URI address;
    @SerializedName("tc")
    private byte[] commitment;

    // no-args constructor for Gson
    private TerminalDetails() {
    }

    ;

    @Override
    public URI getTerminalAddress() {
        return address;
    }

    @Override
    public byte[] getTerminalCommitment() {
        return commitment;
    }

    @Override
    public boolean hasTerminal() {
        // Check that address and commitment are both non-null and non-empty.
        return (
            address != null &&
                address.toString().length() > 0 &&
                commitment != null &&
                commitment.length > 0);
    }
}
