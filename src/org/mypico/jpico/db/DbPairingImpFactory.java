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

import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingImp;
import org.mypico.jpico.data.pairing.PairingImpFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImp;

import com.j256.ormlite.dao.Dao;

/**
 * Implementation of the {@link PairingImpFactory} interface, that creates the implementations of
 * the {@link PairingImp} factory.
 */
public class DbPairingImpFactory implements PairingImpFactory {

    private final Dao<DbPairingImp, Integer> pairingDao;
    private final DbServiceImpFactory dbServiceImpFactory;

    /**
     * Constructor.
     *
     * @param pairingDao          The data access object used to access pairings in the database.
     * @param dbServiceImpFactory Factory for creating objects for accessing {@link Service}s in
     *                            the database.
     */
    public DbPairingImpFactory(
        final Dao<DbPairingImp, Integer> pairingDao,
        final DbServiceImpFactory dbServiceImpFactory) {
        this.pairingDao = pairingDao;
        this.dbServiceImpFactory = dbServiceImpFactory;
    }

    @Override
    public DbPairingImp getImp(String name, Service service) {
        ServiceImp imp = service.getImp();
        DbServiceImp dbImp;
        if (imp instanceof DbServiceImp) {
            dbImp = (DbServiceImp) imp;
        } else {
            dbImp = dbServiceImpFactory.getImp(service);
        }
        return new DbPairingImp(name, dbImp, pairingDao);
    }

    @Override
    public DbPairingImp getImp(Pairing pairing) {
        return getImp(pairing.getName(), pairing.getService());
    }

    /*
     * // Test
     * 
     * public List<Pairing> getPairingsByServiceId(int serviceId) throws SQLException {
     * Dao<DbServiceImp, Integer> serviceDao; PreparedQuery<DbPairingImp> query = null; // build
     * query using pairingDao and serviceDao
     * 
     * List<DbPairingImp> imps = pairingDao.query(query); List<Pairing> pairings = new
     * ArrayList<Pairing>(imps.size()); for (DbPairingImp imp : imps) { pairings.add(new
     * Pairing(imp)); } return pairings; }
     */
}
