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

/**
 * Abstract base class for all visual codes. All visual codes have a type and the commitment
 * provided by that service which will be checked when the Pico authenticates to it (for example, see
 * {@link LensPairingVisualCode#getServiceCommitment()},
 * {@link KeyPairingVisualCode#getServiceCommitment()} or
 * {@link KeyAuthenticationVisualCode#getServiceCommitment()}).
 * For example this commitment may be the hash of the service's long term public key.
 * <p>
 * <p> Subclasses can extend this class to add additional information to the
 * visual code for a specific purpose.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public abstract class VisualCode {

    /**
     * Identifies the type of visual code, this is a work around for GSON not handling class
     * hierarchies.
     */
    @SerializedName("t")
    protected String type;

    /**
     * Constructor.
     *
     * @param type The type of the visual code.
     */
    protected VisualCode(final String type) {
        this.type = checkNotNull(type);
    }

    /**
     * Get the type of the visual code.
     *
     * @return the type of the visual code.
     */
    public String getType() {
        return type;
    }

    public boolean isValid() {
        // checking of the type field is done in VisualCodeGson#deserialise.
        return true;
    }

}
