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


package org.mypico.jpico.data.service;

import java.net.URI;


/**
 * Interface of a factory which produces concrete {@link ServiceImp} instances.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @see Service
 * @see ServiceImp
 */
public interface ServiceImpFactory {

    /**
     * Get a concrete {@link ServiceImp} instance.
     *
     * @param name       The name of the service.
     * @param address    The address of the service.
     * @param commitment The service commitment.
     * @return a concrete {@link ServiceImp} instance.
     */
    public ServiceImp getImp(String name, URI address, byte[] commitment);

    /**
     * Make a copy of a concrete {@link Service} instance.
     *
     * @param service The {@link Service} to copy.
     * @return The new {@link Service} instance.
     */
    public ServiceImp getImp(Service service);
}
