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


package org.mypico.jpico.data;

import java.io.IOException;

/**
 * An object which can be saved to a permanent data store such as a database.
 *
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public interface Saveable {

    /**
     * Save this object to a permanent data store. The object is responsible for choosing where to
     * save itself to.
     *
     * @throws IOException if an <code>IOException</code> occurs whilst saving.
     */
    public void save() throws IOException;

    /**
     * Check whether or not this saveable object has been saved yet.
     *
     * @return <code>true</code> if it has been saved or <code>false</code> otherwise.
     */
    boolean isSaved();
}
