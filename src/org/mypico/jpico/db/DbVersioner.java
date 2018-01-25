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

import java.sql.SQLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;

/**
 * This class exists basically to organise the code related to database updates
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 */
public class DbVersioner {

    private static final Logger LOGGER = LoggerFactory.getLogger(
        DbVersioner.class.getSimpleName());

    /**
     * The current version of the database. This number should increase by 1 at
     * every change. For historical reasons are starting at 21.
     */
    public static final int CURRENT_VERSION = 21;

    /**
     * Creates a database from scratch
     *
     * @param connection The connection to the database source.
     * @throws SQLException in case of an error creating the database.
     */
    public static void createDatabase(ConnectionSource connection) throws SQLException {
        LOGGER.debug("Creating database tables...");
        TableUtils.createTable(connection, DbServiceImp.class);
        TableUtils.createTable(connection, DbPairingImp.class);
        TableUtils.createTable(connection, DbKeyPairingImp.class);
        TableUtils.createTable(connection, DbLensPairingImp.class);
        TableUtils.createTable(connection, DbSessionImp.class);
        TableUtils.createTable(connection, DbTerminalImp.class);
        LOGGER.info("All database tables created");
    }

    public static void dropDatabase(ConnectionSource connection) {
        try {
            LOGGER.debug("Dropping database tables...");
            // true arguments means any SQLExceptions which occur will be caught
            // and suppressed. This flag is set, because otherwise the
            // addition of new tables (or possibly changes to table which affect
            // their indices) causes runtime exceptions
            TableUtils.dropTable(connection, DbServiceImp.class, true);
            TableUtils.dropTable(connection, DbKeyPairingImp.class, true);
            TableUtils.dropTable(connection, DbLensPairingImp.class, true);
            TableUtils.dropTable(connection, DbPairingImp.class, true);
            TableUtils.dropTable(connection, DbSessionImp.class, true);
            TableUtils.dropTable(connection, DbTerminalImp.class, true);
            LOGGER.debug("All tables dropped");
        } catch (SQLException e) {
            LOGGER.error("Database upgrade failed", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Updates the database connected from an old version to a new version version
     *
     * @param connection A ConnectionSource to the database
     * @param oldVersion Old version number
     * @throws SQLException In case an error occurs during the upgrade process.
     */
    public static void upgradeDatabase(ConnectionSource connection, int oldVersion) throws SQLException {
        LOGGER.info("Upgrading database from version " + oldVersion + " to " + CURRENT_VERSION);

        assert (oldVersion <= CURRENT_VERSION); // Just for sanity

        if (oldVersion < 21) {
            // We were not doing version control on databases older than 21. In this case we can only delete
            // everything and recreate (This was the approach used by the Pico Android App in the past)
            dropDatabase(connection);
            createDatabase(connection);
        }
    }

}
