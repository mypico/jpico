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

import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImpFactory;

import com.j256.ormlite.dao.Dao;

/**
 * Implementation of the {@link ServiceImpFactory} interface which produces concrete
 * {@link org.mypico.jpico.data.service.ServiceImp} instances from the database.
 *
 * @see org.mypico.jpico.data.service.ServiceImp
 */
public class DbServiceImpFactory implements ServiceImpFactory {

    private final Dao<DbServiceImp, Integer> serviceDao;

    /**
     * Constructor.
     *
     * @param serviceDao The data access object for accessing services in the database.
     */
    public DbServiceImpFactory(final Dao<DbServiceImp, Integer> serviceDao) {
        this.serviceDao = serviceDao;
    }

    @Override
    public DbServiceImp getImp(String name, URI address, byte[] commitment) {
        return new DbServiceImp(name, address, commitment, serviceDao);
    }

    @Override
    public DbServiceImp getImp(Service service) {
        return getImp(
            service.getName(),
            service.getAddress(),
            service.getCommitment());
    }
}
