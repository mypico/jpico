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

import java.io.IOException;
import java.sql.SQLException;

import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingAccessor;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.SelectArg;

/**
 * Implementation of the {@link PairingAccessor} interface for accessing {@link Pairing}s
 * stored in the database.
 */
public class DbPairingAccessor implements PairingAccessor {

    private final Dao<DbPairingImp, Integer> pairingDao;

    /**
     * Constructor.
     *
     * @param pairingDao Data access object for accessing the pairings in the database.
     */
    public DbPairingAccessor(final Dao<DbPairingImp, Integer> pairingDao) {
        this.pairingDao = pairingDao;
    }

    @Override
    public Pairing getPairingById(int id) throws IOException {
        try {
            // Build query
            SelectArg idArg = new SelectArg();
            PreparedQuery<DbPairingImp> query = pairingDao.queryBuilder()
                .where()
                .eq(DbPairingImp.ID_COLUMN, idArg)
                .prepare();
            idArg.setValue(id);

            // Execute query
            final DbPairingImp pairingImp = pairingDao.queryForFirst(query);

            if (pairingImp != null) {
                pairingImp.setDao(pairingDao);
                return new Pairing(pairingImp);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
