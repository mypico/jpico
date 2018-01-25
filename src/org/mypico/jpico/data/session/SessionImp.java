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

import java.util.Date;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.Saveable;
import org.mypico.jpico.data.pairing.Pairing;

/**
 * Interface of concrete implementations underlying {@link Session} instances.
 * <p>
 * <p>
 * This interface is part of a <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge
 * pattern</a>. Each <code>Session</code> instance has a reference to a concrete {@link SessionImp}
 * instance. See {@link org.mypico.jpico.test.data.session} package documentation for more information
 * on this pattern.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see Session
 * @see SessionImpFactory
 */
public interface SessionImp extends Saveable {

    /**
     * Get the session id.
     *
     * @return the session id.
     */
    int getId();

    /**
     * Get the remote id of the session.
     *
     * @return the session's remote id.
     */
    String getRemoteId();

    /**
     * Get the secret key for the session.
     *
     * @return the secret key.
     */
    SecretKey getSecretKey();

    /**
     * Get the pairing associated with this session.
     *
     * @return the pairing.
     */
    Pairing getPairing();

    /**
     * Get the session status.
     *
     * @return the session status.
     * @see org.mypico.jpico.data.session.Session.Status
     */
    Session.Status getStatus();

    /**
     * Set the session status.
     *
     * @param status the session status to set.
     * @see org.mypico.jpico.data.session.Session.Status
     */
    void setStatus(Session.Status status);

    /**
     * Get any error associated with the session.
     *
     * @return the error.
     */
    Session.Error getError();

    /**
     * Set the error associated with the session.
     *
     * @param error the error to set.
     */
    void setError(Session.Error error);

    /**
     * Get the last date and time that this session reauthenticated.
     *
     * @return the last date and time of successful authentication.
     */
    Date getLastAuthDate();

    /**
     * Set the last date and time that this session successfully reauthenticated.
     */
    void setLastAuthDate(Date date);

    /**
     * Get whether there is an {@link AuthToken} associated with this session.
     *
     * @return true if there is an {@link AuthToken} associated with this session, false o/w.
     */
    boolean hasAuthToken();

    /**
     * Get the {@link AuthToken} associated with this session, if there is one.
     *
     * @return the {@link AuthToken} associated with this session, if there is one.
     * @throws IllegalStateException not currently thrown.
     */
    AuthToken getAuthToken() throws IllegalStateException;

    /**
     * Clear the {@link AuthToken}.
     */
    void clearAuthToken();
}
