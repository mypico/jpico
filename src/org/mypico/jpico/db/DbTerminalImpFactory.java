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

import java.security.PrivateKey;
import java.security.PublicKey;

import org.mypico.jpico.data.terminal.Terminal;

import com.j256.ormlite.dao.Dao;

/**
 * Implementation of the {@link org.mypico.jpico.data.terminal.Terminal.ImpFactory} interface which produces concrete
 * {@link org.mypico.jpico.data.terminal.Terminal.Imp} instances.
 */
public class DbTerminalImpFactory implements Terminal.ImpFactory {

    private final Dao<DbTerminalImp, Integer> dao;

    /**
     * Constructor.
     *
     * @param dao Data access object for accessing terminals in the database.
     */
    public DbTerminalImpFactory(Dao<DbTerminalImp, Integer> dao) {
        this.dao = dao;
    }

    @Override
    public DbTerminalImp getImp(
        String name,
        byte[] commitment,
        PublicKey picoPublicKey,
        PrivateKey picoPrivateKey) {
        return new DbTerminalImp(name, commitment, picoPublicKey, picoPrivateKey, dao);
    }

    @Override
    public DbTerminalImp getImp(Terminal terminal) {
        return getImp(
            terminal.getName(),
            terminal.getCommitment(),
            terminal.getPicoPublicKey(),
            terminal.getPicoPrivateKey());
    }

}
