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

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.SQLException;
import java.util.Date;
import java.util.Map;
import java.util.List;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImp;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.Session.Error;
import org.mypico.jpico.data.session.Session.Status;
import org.mypico.jpico.data.terminal.Terminal;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.support.ConnectionSource;

/**
 * Implementation of the {@link DataFactory} interface for creating concrete instances of the
 * objects stored in the database.
 */
public class DbDataFactory implements DataFactory {

    private final DbServiceImpFactory dbServiceImpFactory;
    private final DbPairingImpFactory dbPairingImpFactory;
    private final DbKeyPairingImpFactory dbKeyPairingImpFactory;
    private final DbLensPairingImpFactory dbCredentialPairingImpFactory;
    private final DbSessionImpFactory dbSessionImpFactory;
    private final DbTerminalImpFactory dbTerminalImpFactory;

    /**
     * Constructor.
     *
     * @param dbConnection The database connectiono to use.
     * @throws SQLException thrown if there's an error accessing the database.
     */
    public DbDataFactory(final ConnectionSource dbConnection)
        throws SQLException {

        final Dao<DbServiceImp, Integer> serviceDao =
            DaoManager.createDao(dbConnection, DbServiceImp.class);
        final Dao<DbPairingImp, Integer> pairingDao =
            DaoManager.createDao(dbConnection, DbPairingImp.class);
        final Dao<DbKeyPairingImp, Integer> keyPairingDao =
            DaoManager.createDao(dbConnection, DbKeyPairingImp.class);
        final Dao<DbLensPairingImp, Integer> credentialPairingDao =
            DaoManager.createDao(dbConnection, DbLensPairingImp.class);
        final Dao<DbSessionImp, Integer> sessionDao =
            DaoManager.createDao(dbConnection, DbSessionImp.class);
        final Dao<DbTerminalImp, Integer> terminalDao =
            DaoManager.createDao(dbConnection, DbTerminalImp.class);

        dbServiceImpFactory = new DbServiceImpFactory(serviceDao);
        dbPairingImpFactory = new DbPairingImpFactory(
            pairingDao, dbServiceImpFactory);
        dbKeyPairingImpFactory = new DbKeyPairingImpFactory(
            keyPairingDao, pairingDao, dbServiceImpFactory);
        dbCredentialPairingImpFactory = new DbLensPairingImpFactory(
            credentialPairingDao, pairingDao, dbServiceImpFactory);
        dbSessionImpFactory = new DbSessionImpFactory(
            sessionDao, dbPairingImpFactory);
        dbTerminalImpFactory = new DbTerminalImpFactory(terminalDao);
    }

    @Override
    public ServiceImp getImp(String name, URI address, byte[] commitment) {
        return dbServiceImpFactory.getImp(name, address, commitment);
    }

    @Override
    public DbServiceImp getImp(Service service) {
        return dbServiceImpFactory.getImp(service);
    }

    @Override
    public DbPairingImp getImp(String name, Service service) {
        return dbPairingImpFactory.getImp(name, service);
    }

    @Override
    public DbPairingImp getImp(Pairing pairing) {
        return dbPairingImpFactory.getImp(pairing);
    }

    @Override
    public DbSessionImp getImp(
        String remoteId,
        SecretKey secretKey,
        Pairing pairing,
        AuthToken authToken,
        Date lastAuthDate,
        Status status,
        Error error) {
        return dbSessionImpFactory.getImp(
            remoteId,
            secretKey,
            pairing,
            authToken,
            lastAuthDate,
            status,
            error);
    }

    @Override
    public DbSessionImp getImp(Session session) {
        return dbSessionImpFactory.getImp(session);
    }

    @Override
    public DbKeyPairingImp getImp(
        String name,
        Service service,
        PublicKey publicKey,
        PrivateKey privateKey,
        String extraData) {
        return dbKeyPairingImpFactory.getImp(
            name, service, publicKey, privateKey, extraData);
    }

    @Override
    public DbKeyPairingImp getImp(
        String name, Service service, KeyPair keyPair, String extraData) {
        return dbKeyPairingImpFactory.getImp(name, service, keyPair, extraData);
    }

    @Override
    public DbKeyPairingImp getImp(KeyPairing keyPairing) {
        return dbKeyPairingImpFactory.getImp(keyPairing);
    }

    @Override
    public DbLensPairingImp getImp(String name,
                                   Service service, Map<String, String> credentials, List<String> privateFields) {
        return dbCredentialPairingImpFactory.getImp(
            name, service, credentials, privateFields);
    }

    @Override
    public DbLensPairingImp getImp(LensPairing credentialPairing) {
        return dbCredentialPairingImpFactory.getImp(credentialPairing);
    }

    @Override
    public Terminal.Imp getImp(
        String name, byte[] commitment, PublicKey picoPublicKey, PrivateKey picoPrivateKey) {
        return dbTerminalImpFactory.getImp(name, commitment, picoPublicKey, picoPrivateKey);
    }

    @Override
    public Terminal.Imp getImp(Terminal terminal) {
        return dbTerminalImpFactory.getImp(terminal);
    }
}
