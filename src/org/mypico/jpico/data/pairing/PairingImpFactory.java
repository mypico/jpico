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

import org.mypico.jpico.data.service.Service;

/**
 * Interface of a factory which produces concrete {@link PairingImp} instances.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see Pairing
 * @see PairingImp
 */
public interface PairingImpFactory {

    /**
     * Get a concrete {@link PairingImp} instance.
     *
     * @param name    The name of the pairing.
     * @param service The service the pairing is associated with.
     * @return the concrete {@link PairingImp} instance.
     */
    public PairingImp getImp(String name, Service service);

    /**
     * Make a new copy of a concrete {@link PairingImp} instance.
     *
     * @param pairing The {@link PairingImp} to copy.
     * @return the new concrete {@link PairingImp} instance.
     */
    public PairingImp getImp(Pairing pairing);
}
