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


package org.mypico.jpico.data.session;

import java.io.IOException;

/**
 * Interface of an "accessor" which returns {@link Session} instances saved in a data store.
 *
 * @author Graeme Jenkinson &lt;gcj21@cl.cam.ac.uk&gt;
 * @see Session
 */
public interface SessionAccessor {

    /**
     * Query the store for a session with a given ID.
     *
     * @param sessionId ID to query for.
     * @return <code>Session</code> instance with matching ID or <code>null</code> if none could
     * be found.
     * @throws IOException if an <code>IOException</code> occurred whilst querying the data store.
     */
    public Session getSessionById(int sessionId) throws IOException;
}
