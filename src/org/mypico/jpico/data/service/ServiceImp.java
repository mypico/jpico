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

import org.mypico.jpico.data.Saveable;

/**
 * Interface of concrete implementations underlying {@link Service} instances.
 * <p>
 * <p>
 * This interface is part of a <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge
 * pattern</a>. Each <code>Service</code> instance has a reference to a concrete {@link ServiceImp}
 * instance. See {@link org.mypico.jpico.test.data.service} package documentation for more information
 * on this pattern.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see Service
 * @see ServiceImpFactory
 */
public interface ServiceImp extends Saveable {

    /**
     * Get the service id.
     *
     * @return the service id.
     */
    int getId();

    /**
     * Get the service name.
     *
     * @return the service name.
     */
    String getName();

    /**
     * Get the service address.
     *
     * @return the service address.
     */
    URI getAddress();

    /**
     * Get the service commitment.
     *
     * @return the service commitment.
     */
    byte[] getCommitment();

    /**
     * Set the service address.
     *
     * @param checkNotNull the service address to set.
     */
    void setAddress(URI checkNotNull);
}
