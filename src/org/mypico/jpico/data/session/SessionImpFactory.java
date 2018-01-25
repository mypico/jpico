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
import org.mypico.jpico.data.pairing.Pairing;

/**
 * Interface of a factory which produces concrete {@link SessionImp} instances.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see Session
 * @see SessionImp
 */
public interface SessionImpFactory {

    /**
     * Get a concrete instance of a {@link SessionImp}.
     *
     * @param remoteId     The id of the session on the remote device.
     * @param secretKey    The secret key for the session.
     * @param pairing      The pairing associated with the session.
     * @param authToken    The auth token for the session.
     * @param lastAuthDate The last time and data auhentication took place.
     * @param status       The status of the session.
     * @param error        Any errors set on the session.
     * @return the concrete instance of a {@link SessionImp} instance.
     */
    public SessionImp getImp(
        String remoteId,
        SecretKey secretKey,
        Pairing pairing,
        AuthToken authToken,
        Date lastAuthDate,
        Session.Status status,
        Session.Error error);

    /**
     * Make a copy of a concrete of a {@link Session} instance
     *
     * @param session The {@link Session} to copy
     * @return the new concrete {@link SessionImp} instance.
     */
    public SessionImp getImp(Session session);
}
