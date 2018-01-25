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

import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionAccessor;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.SelectArg;

/**
 * Implementation of the {@link SessionAccessor} interface for accessing {@link Session}s
 * stored in the database.
 */
public class DbSessionAccessor implements SessionAccessor {

    private final Dao<DbSessionImp, Integer> sessionDao;

    /**
     * Constructor.
     *
     * @param sessionDao The data access object for accessing sessions in the database.
     */
    public DbSessionAccessor(
        final Dao<DbSessionImp, Integer> sessionDao) {
        this.sessionDao = checkNotNull(sessionDao);
    }

    @Override
    public Session getSessionById(final int sessionId)
        throws IOException {
        try {
            // Build query
            final SelectArg sessionIdArg = new SelectArg();
            final PreparedQuery<DbSessionImp> query =
                sessionDao.queryBuilder()
                    .where()
                    .eq(DbSessionImp.ID_COLUMN, sessionIdArg)
                    .prepare();

            // Execute query
            sessionIdArg.setValue(sessionId);
            final DbSessionImp imp =
                sessionDao.queryForFirst(query);

            // Prepare result
            if (imp != null) {
                imp.setDao(sessionDao);
                return new Session(imp);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}