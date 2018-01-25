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

import java.io.IOException;
import java.util.Date;

import org.mypico.jpico.data.Saveable;
import org.mypico.jpico.data.service.Service;

/**
 * Interface of concrete implementations underlying {@link Pairing} instances.
 * <p>
 * <p>
 * This interface is part of a <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge
 * pattern</a>. Each <code>Pairing</code> instance has a reference to a concrete {@link PairingImp}
 * instance. See {@link org.mypico.jpico.test.data.pairing} package documentation for more information
 * on this pattern.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see Pairing
 * @see PairingImpFactory
 */
public interface PairingImp extends Saveable {

    /**
     * Get the pairing id.
     *
     * @return the pairing id.
     */
    int getId();

    /**
     * Get the service associated with the pairing.
     *
     * @return the service associated with the pairing.
     */
    Service getService();

    /**
     * Get the name of the pairing.
     *
     * @return the pairing name.
     */
    String getName();

    /**
     * Set the name of the pairing.
     *
     * @param name the pairing name to set.
     */
    void setName(String name);

    /**
     * Get the date the pairing was created.
     *
     * @return the date created.
     */
    Date getDateCreated();

    /**
     * Delete the pairing.
     *
     * @throws IOException thrown if there is an exception accessing the database to delete the
     *                     pairing.
     */
    public void delete() throws IOException;
}
