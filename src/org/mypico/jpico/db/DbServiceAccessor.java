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

import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceAccessor;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.SelectArg;

/**
 * Implementation of the {@link ServiceAccessor} interface of an "accessor" which returns
 * {@link Service} instances saved in the database.
 *
 * @see Service
 */
public class DbServiceAccessor implements ServiceAccessor {

    private final Dao<DbServiceImp, Integer> serviceDao;

    /**
     * Constructor.
     *
     * @param serviceDao The data access object for accessing the services in the database.
     */
    public DbServiceAccessor(final Dao<DbServiceImp, Integer> serviceDao) {
        this.serviceDao = serviceDao;
    }

    @Override
    public Service getServiceById(int serviceId) throws IOException {
        try {
            // Build query
            SelectArg idArg = new SelectArg();
            PreparedQuery<DbServiceImp> query = serviceDao.queryBuilder()
                .where()
                .eq(DbServiceImp.ID_COLUMN, idArg)
                .prepare();
            idArg.setValue(serviceId);

            // Execute query
            final DbServiceImp serviceImp = serviceDao.queryForFirst(query);

            if (serviceImp != null) {
                serviceImp.setDao(serviceDao);
                return new Service(serviceImp);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public Service getServiceByCommitment(byte[] commitment)
        throws IOException {
        try {
            // Build query
            SelectArg commitArg = new SelectArg();
            PreparedQuery<DbServiceImp> query = serviceDao.queryBuilder()
                .where()
                .eq(DbServiceImp.COMMITMENT_COLUMN, commitArg)
                .prepare();
            commitArg.setValue(DbServiceImp.stringifyCommitment(commitment));

            // Execute query
            final DbServiceImp serviceImp = serviceDao.queryForFirst(query);
            if (serviceImp != null) {
                serviceImp.setDao(serviceDao);
                return new Service(serviceImp);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
