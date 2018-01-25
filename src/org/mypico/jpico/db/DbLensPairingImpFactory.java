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

import java.util.Map;

import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.LensPairingImpFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImp;

import java.util.List;

import com.j256.ormlite.dao.Dao;

/**
 * Implementation of the {@link LensPairingImpFactory} interface which produces concrete
 * {@link org.mypico.jpico.data.pairing.LensPairingImp} instances.
 */
public class DbLensPairingImpFactory
    implements LensPairingImpFactory {

    private final Dao<DbLensPairingImp, Integer> lensPairingDao;
    private final Dao<DbPairingImp, Integer> pairingDao;
    private final DbServiceImpFactory dbServiceImpFactory;

    /**
     * Constructor.
     *
     * @param lensPairingDao      Data access object for accessing the lens pairings in the database.
     * @param pairingDao          Data access object for accessing the pairings in the database.
     * @param dbServiceImpFactory Data access object for accessing the services in the database.
     */
    public DbLensPairingImpFactory(
        final Dao<DbLensPairingImp, Integer> lensPairingDao,
        final Dao<DbPairingImp, Integer> pairingDao,
        final DbServiceImpFactory dbServiceImpFactory) {
        this.pairingDao = pairingDao;
        this.lensPairingDao = lensPairingDao;
        this.dbServiceImpFactory = dbServiceImpFactory;
    }

    @Override
    public DbLensPairingImp getImp(
        String name,
        Service service,
        Map<String, String> credentials,
        List<String> privateFields) {
        ServiceImp serviceImp = service.getImp();
        DbServiceImp dbServiceImp;
        if (serviceImp instanceof DbServiceImp) {
            dbServiceImp = (DbServiceImp) serviceImp;
        } else {
            dbServiceImp = dbServiceImpFactory.getImp(service);
        }
        return new DbLensPairingImp(
            name,
            dbServiceImp,
            credentials,
            privateFields,
            pairingDao,
            lensPairingDao);
    }

    @Override
    public DbLensPairingImp getImp(
        LensPairing credentialPairing) {
        return getImp(
            credentialPairing.getName(),
            credentialPairing.getService(),
            credentialPairing.getCredentials(),
            credentialPairing.getPrivateFields());
    }
}
