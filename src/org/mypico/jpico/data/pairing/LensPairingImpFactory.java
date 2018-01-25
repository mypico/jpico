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


package org.mypico.jpico.data.pairing;

import java.util.Map;

import org.mypico.jpico.data.service.Service;

import java.util.List;

/**
 * Interface of a factory which produces concrete {@link LensPairingImp} instances.
 *
 * @author Claudio Dettoni Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see LensPairing
 * @see LensPairingImp
 */
public interface LensPairingImpFactory {

    /**
     * Get a concrete {@link LensPairingImp} instance
     *
     * @param name          The name of the service the pairing is associated with.
     * @param service       The service the pairing is associated with.
     * @param credentials   The credentials needed for logging in to the service.
     * @param privateFields The private keys from the credentials.
     * @return the concrete {@link LensPairingImp} instance.
     */
    public LensPairingImp getImp(
        String name, Service service, Map<String, String> credentials, List<String> privateFields);

    /**
     * Make a new copy of a concrete {@link LensPairingImp} instance.
     *
     * @param credentialPairing The {@link LensPairingImp} to copy.
     * @return the new concrete {@link LensPairingImp} instance.
     */
    public LensPairingImp getImp(LensPairing credentialPairing);
}
