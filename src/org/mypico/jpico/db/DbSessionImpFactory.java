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


package org.mypico.jpico.db;

import java.util.Date;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingImp;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImpFactory;

import com.j256.ormlite.dao.Dao;

/**
 * Implementation of the {@link SessionImpFactory} interface which produces concrete
 * {@link org.mypico.jpico.data.session.SessionImp} instances from the database.
 *
 * @see org.mypico.jpico.data.session.SessionImp
 */
public class DbSessionImpFactory implements SessionImpFactory {

    Dao<DbSessionImp, Integer> sessionDao;
    private DbPairingImpFactory dbPairingImpFactory;

    /**
     * Constructor.
     *
     * @param sessionDao          Data access object for accessing the sessions in the database.
     * @param dbPairingImpFactory Pairing factory for the database.
     */
    public DbSessionImpFactory(
        final Dao<DbSessionImp, Integer> sessionDao,
        final DbPairingImpFactory dbPairingImpFactory) {
        this.sessionDao = sessionDao;
        this.dbPairingImpFactory = dbPairingImpFactory;
    }

    @Override
    public DbSessionImp getImp(
        String remoteId,
        SecretKey secretKey,
        Pairing pairing,
        AuthToken authToken,
        Date lastAuthDate,
        Session.Status status,
        Session.Error error) {
        PairingImp imp = pairing.getImp();
        DbPairingImp dbImp;
        if (imp instanceof DbPairingImp) {
            dbImp = (DbPairingImp) imp;
        } else {
            dbImp = dbPairingImpFactory.getImp(pairing);
        }
        return new DbSessionImp(
            remoteId,
            secretKey,
            dbImp,
            authToken,
            lastAuthDate,
            status,
            error,
            sessionDao);
    }

    @Override
    public DbSessionImp getImp(Session session) {
        return getImp(
            session.getRemoteId(),
            session.getSecretKey(),
            session.getPairing(),
            session.hasAuthToken() ? session.getAuthToken() : null,
            session.getLastAuthDate(),
            session.getStatus(),
            session.getError());
    }
}
