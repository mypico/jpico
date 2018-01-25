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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.pairing.KeyPairingImp;
import org.mypico.jpico.data.pairing.KeyPairingImpFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImp;

import com.j256.ormlite.dao.Dao;

/**
 * Implementation of the {@link KeyPairingImpFactory} interface which produces concrete
 * {@link KeyPairingImp} instances.
 */
public class DbKeyPairingImpFactory implements KeyPairingImpFactory {

    private final Dao<DbKeyPairingImp, Integer> keyPairingDao;
    private final Dao<DbPairingImp, Integer> pairingDao;
    private final DbServiceImpFactory dbServiceImpFactory;

    /**
     * Constructor.
     *
     * @param keyPairingDao       Data access object for accessing the key pairings in the database.
     * @param pairingDao          Data access object for accessing the pairings in the database.
     * @param dbServiceImpFactory Data access object for accessing the services in the database.
     */
    public DbKeyPairingImpFactory(
        final Dao<DbKeyPairingImp, Integer> keyPairingDao,
        final Dao<DbPairingImp, Integer> pairingDao,
        final DbServiceImpFactory dbServiceImpFactory) {
        this.pairingDao = pairingDao;
        this.keyPairingDao = keyPairingDao;
        this.dbServiceImpFactory = dbServiceImpFactory;
    }

    @Override
    public DbKeyPairingImp getImp(
        String name,
        Service service,
        PublicKey publicKey,
        PrivateKey privateKey,
        String extraData) {
        ServiceImp serviceImp = service.getImp();
        DbServiceImp dbServiceImp;
        if (serviceImp instanceof DbServiceImp) {
            dbServiceImp = (DbServiceImp) serviceImp;
        } else {
            dbServiceImp = dbServiceImpFactory.getImp(service);
        }
        return new DbKeyPairingImp(
            name,
            dbServiceImp,
            publicKey,
            privateKey,
            extraData,
            pairingDao,
            keyPairingDao);
    }

    @Override
    public DbKeyPairingImp getImp(
        String name, Service service, KeyPair keyPair, String extraData) {
        return getImp(
            name, service, keyPair.getPublic(), keyPair.getPrivate(), extraData);
    }

    @Override
    public DbKeyPairingImp getImp(KeyPairing keyPairing) {
        return getImp(
            keyPairing.getName(),
            keyPairing.getService(),
            keyPairing.getPublicKey(),
            keyPairing.getPrivateKey(),
            keyPairing.getExtraData());
    }
}
