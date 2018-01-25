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
import java.util.ArrayList;
import java.util.List;

import org.mypico.jpico.data.terminal.Terminal;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.SelectArg;

/**
 * Implementation of the {@link org.mypico.jpico.data.terminal.Terminal.Accessor} interface for
 * accessing {@link Terminal}s stored in the database.
 */
public class DbTerminalAccessor implements Terminal.Accessor {

    private final Dao<DbTerminalImp, Integer> dao;

    /**
     * Constructor.
     *
     * @param dao Data access object for accessing terminals in the database.
     */
    public DbTerminalAccessor(final Dao<DbTerminalImp, Integer> dao) {
        this.dao = dao;
    }

    @Override
    public Terminal getTerminalById(int id) throws IOException {
        try {
            // Build query
            SelectArg idArg = new SelectArg();
            PreparedQuery<DbTerminalImp> query = dao.queryBuilder()
                .where()
                .eq(DbTerminalImp.ID_COLUMN, idArg)
                .prepare();
            idArg.setValue(id);

            // Execute query
            final DbTerminalImp imp = dao.queryForFirst(query);

            if (imp != null) {
                imp.setDao(dao);
                return new Terminal(imp);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public Terminal getTerminalByCommitment(byte[] commitment)
        throws IOException {
        try {
            // Build query
            SelectArg commitArg = new SelectArg();
            PreparedQuery<DbTerminalImp> query = dao.queryBuilder()
                .where()
                .eq(DbServiceImp.COMMITMENT_COLUMN, commitArg)
                .prepare();
            commitArg.setValue(DbServiceImp.stringifyCommitment(commitment));

            // Execute query
            final DbTerminalImp imp = dao.queryForFirst(query);
            if (imp != null) {
                imp.setDao(dao);
                return new Terminal(imp);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public List<Terminal> getAllTerminals() throws IOException {
        try {
            List<DbTerminalImp> imps = dao.queryForAll();
            ArrayList<Terminal> terminals = new ArrayList<Terminal>(imps.size());
            for (DbTerminalImp imp : imps) {
                imp.setDao(dao);
                terminals.add(new Terminal(imp));
            }
            return terminals;
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
