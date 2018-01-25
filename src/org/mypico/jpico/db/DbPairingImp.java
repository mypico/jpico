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
import java.security.InvalidParameterException;
import java.sql.SQLException;
import java.util.Date;

import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingImp;
import org.mypico.jpico.data.service.Service;

import com.google.common.base.Preconditions;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * Implementation of the {@link PairingImp} interface. This actually performs the process of
 * storing and retrieving the pairings to/from the database.
 */
@DatabaseTable(tableName = DbPairingImp.PAIRINGS_TABLE)
public class DbPairingImp implements PairingImp {

    static final String PAIRINGS_TABLE = "pairings";

    static final String ID_COLUMN = "id";
    static final String NAME_COLUMN = "name";
    static final String SERVICE_COLUMN = "service_id";
    static final String DATE_CREATED_COLUMN = "date_created";

    /**
     * Initial value of a DbPairing's id, before it is saved to the database. DbPairing's are
     * automatically assigned an id when they are saved to the database for the first time.
     */
    public static final int UNSAVED_ID = 0;

    @DatabaseField(
        columnName = ID_COLUMN,
        generatedId = true,
        throwIfNull = true,
        useGetSet = true)
    private int id;

    @DatabaseField(
        columnName = NAME_COLUMN,
        index = true,
        canBeNull = false,
        useGetSet = true)
    private String name;

    @DatabaseField(
        columnName = SERVICE_COLUMN,
        foreign = true,
        foreignAutoRefresh = true,
        foreignAutoCreate = true,
        canBeNull = false,
        useGetSet = true)
    private DbServiceImp dbService;

    @DatabaseField(
        columnName = DATE_CREATED_COLUMN,
        canBeNull = false,
        useGetSet = true)
    private Date dateCreated = new Date();

    private Dao<DbPairingImp, Integer> dao;

    /**
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public DbPairingImp() {
    }

    DbPairingImp(
        final String name,
        final DbServiceImp dbService,
        final Dao<DbPairingImp, Integer> dao) {
        // Validate arguments
        Pairing.checkName(name);
        assert (dbService != null);

        this.id = UNSAVED_ID;
        this.name = name;
        this.dbService = dbService;
        this.dao = dao;
    }

    /**
     * Set the data access object to use for interacting with the database.
     *
     * @param dao the data access object to use.
     */
    void setDao(final Dao<DbPairingImp, Integer> dao) {
        this.dao = dao;
    }

    @Override
    public void save() throws IOException {
        Preconditions.checkNotNull(
            dao, "DbPairingImp cannot be saved with null DAO");
        try {
            dao.createOrUpdate(this);
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public boolean isSaved() {
        return (id != UNSAVED_ID);
    }

    /**
     * @param id new id value for this DbPairing.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setId(final int id) {
        this.id = id;
    }

    /**
     * Return the id of this DbPairing. The id of a DbPairing is automatically assigned when it is
     * first saved to the database. This id (see {@link #ID_COLUMN ID_COLUMN}) is the primary key in
     * the pairings database table.
     *
     * @return id of this DbPairing.
     * @see org.mypico.jpico.db.DbTerminalImp#UNSAVED_ID
     */
    @Override
    public int getId() {
        return id;
    }

    /**
     * @param dbService new service value for this DbPairing.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setDbService(final DbServiceImp dbService) {
        // Verify the method's preconditions
        if (dbService == null) {
            throw new InvalidParameterException(
                "Pairing's service cannot be set to null");
        }
        this.dbService = dbService;
    }

    @Deprecated
    public DbServiceImp getDbService() {
        return dbService;
    }

    @Override
    public Service getService() {
        return new Service(dbService);
    }

    @Override
    public void setName(final String name) {
        // Verify the method's preconditions
        if (name == null) {
            throw new InvalidParameterException(
                "Pairing's name cannot be set to null or empty");
        }
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    /**
     * @param date new date created value for this DbPairing.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setDateCreated(final Date date) {
        // Verify the method's preconditions
        if (date == null) {
            throw new InvalidParameterException(
                "Pairing's date created cannot be set to null");
        }
        this.dateCreated = date;
    }

    @Override
    public Date getDateCreated() {
        return dateCreated;
    }

    @Override
    public void delete() throws IOException {
        checkNotNull(dao, "cannot be saved with null dao");
        if (isSaved()) {
            try {
                dao.delete(this);
                id = UNSAVED_ID;
            } catch (SQLException e) {
                throw new IOException(e);
            }
        } else {
            throw new IllegalStateException("cannot delete an unsaved pairing");
        }
    }
}
