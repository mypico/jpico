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

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.LensPairingAccessor;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.SelectArg;

/**
 * Implementation of the {@link LensPairingAccessor} interface for accessing {@link LensPairing}s
 * stored in the database.
 */
public class DbLensPairingAccessor implements LensPairingAccessor {

    private final Dao<DbLensPairingImp, Integer> lensPairingDao;
    private final Dao<DbPairingImp, Integer> pairingDao;
    private final Dao<DbServiceImp, Integer> serviceDao;

    /**
     * Constructor.
     *
     * @param lensPairingDao Data access object for accessing the lens pairings in the database.
     * @param pairingDao     Data access object for accessing the pairings in the database.
     * @param serviceDao     Data access object for accessing the services in the database.
     */
    public DbLensPairingAccessor(
        final Dao<DbLensPairingImp, Integer> lensPairingDao,
        final Dao<DbPairingImp, Integer> pairingDao,
        final Dao<DbServiceImp, Integer> serviceDao) {
        this.lensPairingDao = checkNotNull(lensPairingDao);
        this.pairingDao = checkNotNull(pairingDao);
        this.serviceDao = checkNotNull(serviceDao);
    }

    @Override
    public LensPairing getLensPairingById(final int pairingId)
        throws IOException {
        try {
            // Build query
            final SelectArg pairingIdArg = new SelectArg();
            final PreparedQuery<DbLensPairingImp> query =
                lensPairingDao.queryBuilder()
                    .where()
                    .eq(DbKeyPairingImp.PAIRING_COLUMN, pairingIdArg)
                    .prepare();

            // Execute query
            pairingIdArg.setValue(pairingId);
            final DbLensPairingImp imp =
                lensPairingDao.queryForFirst(query);

            // Prepare result
            if (imp != null) {
                imp.setDao(lensPairingDao);
                return new LensPairing(imp);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public List<LensPairing> getLensPairingsByServiceCommitment(
        final byte[] commitment) throws IOException {
        try {
            // Build a query for all services with matching uri
            final SelectArg arg = new SelectArg();
            final QueryBuilder<DbServiceImp, Integer> serviceQb = serviceDao.queryBuilder();
            serviceQb.where().eq(DbServiceImp.COMMITMENT_COLUMN, arg);

            // Join this on a query for pairings
            final QueryBuilder<DbPairingImp, Integer> pairingQb =
                pairingDao.queryBuilder().join(serviceQb);

            // Join this on a query for lens pairings
            final PreparedQuery<DbLensPairingImp> query =
                lensPairingDao.queryBuilder().join(pairingQb).prepare();

            // Execute the query
            arg.setValue(DbServiceImp.stringifyCommitment(commitment));
            final List<DbLensPairingImp> imps = lensPairingDao.query(query);

            // Transform results
            final List<LensPairing> credentialPairings =
                new ArrayList<LensPairing>(imps.size());
            for (DbLensPairingImp imp : imps) {
                imp.setDao(lensPairingDao);
                credentialPairings.add(new LensPairing(imp));
            }
            return credentialPairings;
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public List<LensPairing> getLensPairingsByServiceCommitmentAndCredentials(
        final byte[] commitment, final Map<String, String> credentials) throws IOException {
        try {
            // Build a query for all services with matching uri
            final SelectArg argCommit = new SelectArg();
            final QueryBuilder<DbServiceImp, Integer> serviceQb = serviceDao.queryBuilder();
            serviceQb.where().eq(DbServiceImp.COMMITMENT_COLUMN, argCommit);

            // Join this on a query for pairings

            final QueryBuilder<DbPairingImp, Integer> pairingQb =
                pairingDao.queryBuilder().join(serviceQb);

            // Join this on a query for lens pairings
            //final PreparedQuery<DbLensPairingImp> query =
            //        lensPairingDao.queryBuilder().join(pairingQb).prepare();

            final SelectArg argCred = new SelectArg();
            final QueryBuilder<DbLensPairingImp, Integer> lensQb = lensPairingDao.queryBuilder();
            lensQb.where().eq(DbLensPairingImp.CREDENTIALS_STRING_COLUMN, argCred);
            final PreparedQuery<DbLensPairingImp> query =
                lensQb.join(pairingQb).prepare();

            // Execute the query
            argCommit.setValue(DbServiceImp.stringifyCommitment(commitment));
            argCred.setValue(DbLensPairingImp.jsonifyCredentials(credentials));
            final List<DbLensPairingImp> imps = lensPairingDao.query(query);

            // Transform results
            final List<LensPairing> credentialPairings =
                new ArrayList<LensPairing>(imps.size());
            for (DbLensPairingImp imp : imps) {
                imp.setDao(lensPairingDao);
                credentialPairings.add(new LensPairing(imp));
            }
            return credentialPairings;
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public List<LensPairing> getAllLensPairings() throws IOException {
        final List<DbLensPairingImp> imps;
        try {
            imps = lensPairingDao.queryForAll();
        } catch (SQLException e) {
            throw new IOException(e);
        }

        // Transform results
        final List<LensPairing> lensPairings = new ArrayList<LensPairing>(imps.size());
        for (DbLensPairingImp imp : imps) {
            imp.setDao(lensPairingDao);
            lensPairings.add(new LensPairing(imp));
        }
        return lensPairings;
    }
}