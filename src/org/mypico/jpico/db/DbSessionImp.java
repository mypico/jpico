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


// Copyright University of Cambridge, 2013

package org.mypico.jpico.db;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Date;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImp;

import com.google.common.base.Preconditions;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * A concrete {@link Session} class which persists services to a database using ORMLite object
 * relational mapping annotations. Secret key fields are persisted using a custom persister class.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see Session
 * @see SecretKeyPersister
 */
@DatabaseTable(tableName = DbSessionImp.SESSION_TABLE)
final public class DbSessionImp implements SessionImp {

    static final String SESSION_TABLE = "sessions";

    static final String ID_COLUMN = "id";
    static final String REMOTE_ID_COLUMN = "remote_id";
    static final String SECRET_KEY_COLUMN = "secret_key";
    static final String PAIRING_COLUMN = "pairing_id";
    static final String STATUS_COLUMN = "status";
    static final String ERROR_COLUMN = "error";
    static final String LAST_AUTH_DATE_COLUMN = "last_auth_date";

    /**
     * Initial value of a DbSessionImp's id, before it is saved to the database. DbSessionImps are
     * automatically assigned an id when they are saved to the database for the first time.
     */
    public static final int UNSAVED_ID = 0;

    @DatabaseField(
        columnName = ID_COLUMN,
        generatedId = true, // Primary key -- automatically generated on save
        throwIfNull = true,
        useGetSet = true)
    private int id;

    @DatabaseField(
        columnName = REMOTE_ID_COLUMN,
        index = true,
        canBeNull = true,
        useGetSet = true)
    private String remoteId;

    @DatabaseField(
        columnName = SECRET_KEY_COLUMN,
        canBeNull = true,
        useGetSet = true,
        persisterClass = SecretKeyPersister.class)
    private SecretKey secretKey;

    @DatabaseField(
        columnName = PAIRING_COLUMN,
        foreign = true,
        foreignAutoRefresh = true,
        foreignAutoCreate = true,
        canBeNull = false,
        useGetSet = true)
    private DbPairingImp dbPairing;

    @DatabaseField(
        columnName = STATUS_COLUMN,
        canBeNull = false,
        useGetSet = true)
    private Session.Status status;

    @DatabaseField(
        columnName = ERROR_COLUMN,
        canBeNull = false,
        useGetSet = true)
    private Session.Error error;

    @DatabaseField(
        columnName = LAST_AUTH_DATE_COLUMN,
        unique = true,
        canBeNull = false,
        useGetSet = true)
    private Date lastAuthDate;

    private AuthToken authToken;
    private Dao<DbSessionImp, Integer> dao;

    /**
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public DbSessionImp() {
    }

    DbSessionImp(
        final String remoteId,
        final SecretKey secretKey,
        final DbPairingImp dbPairing,
        final AuthToken authToken,
        final Date lastAuthDate,
        final Session.Status status,
        final Session.Error error,
        final Dao<DbSessionImp, Integer> dao) {
        assert (dbPairing != null);

        this.id = UNSAVED_ID;
        this.remoteId = remoteId;
        this.secretKey = secretKey;
        this.dbPairing = dbPairing;
        this.authToken = authToken;
        this.lastAuthDate = lastAuthDate;
        this.status = status;
        this.error = error;
        this.dao = dao;
    }

    void setDao(final Dao<DbSessionImp, Integer> dao) {
        this.dao = dao;
    }

    @Override
    public void save() throws IOException {
        Preconditions.checkNotNull(
            dao, "DbSessionImp cannot be saved with null DAO");
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
     * @param id new id value for this DbSession.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setId(final int id) {
        validateId(id);
        this.id = id;
    }

    /**
     * Return the id of this DbSession. The id of a DbSession is automatically assigned when it is
     * first saved to the database. This id (see {@link #ID_COLUMN ID_COLUMN}) is the primary key in
     * the services database table.
     *
     * @return id of this DbService.
     * @see DbTerminalImp#UNSAVED_ID
     */
    @Override
    public int getId() {
        return id;
    }

    /**
     * @param remoteId new remote id value for this DbSession.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setRemoteId(final String remoteId) {
        this.remoteId = remoteId;
    }

    @Override
    public String getRemoteId() {
        return remoteId;
    }

    /**
     * @param secretKey new secret key value for this DbSession.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setSecretKey(final SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * @param dbPairing new pairing value for this DbSession.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setDbPairing(final DbPairingImp dbPairing) {
        this.dbPairing = dbPairing;
    }

    @Deprecated
    public DbPairingImp getDbPairing() {
        return dbPairing;
    }

    @Override
    public Pairing getPairing() {
        // TODO can we do better here and return the correct subclass?
        // Maybe, but should we?
        /*
         * Dao<DbKeyPairingImp, Integer> keyPairingDao = null; DbKeyPairingImp keyPairingImp = null;
         * 
         * if ((keyPairingImp = keyPairingDao.queryForEq(DbKeyPairingImp.PAIRING_COLUMN,
         * dbPairing.getId())) != null) { return new KeyPairing(keyPairingImp); } else { return new
         * Pairing(dbPairing); }
         */
        return new Pairing(dbPairing);
    }

    @Override
    public void setStatus(final Session.Status status) {
        this.status = status;
    }

    @Override
    public Session.Status getStatus() {
        return status;
    }

    @Override
    public void setError(final Session.Error error) {
        this.error = error;
    }

    @Override
    public Session.Error getError() {
        return error;
    }

    @Override
    public void setLastAuthDate(final Date lastAuthDate) {
        Session.checkLastAuthDate(lastAuthDate);
        this.lastAuthDate = lastAuthDate;
    }

    @Override
    public Date getLastAuthDate() {
        return lastAuthDate;
    }

    @Override
    public boolean hasAuthToken() {
        return (authToken != null);
    }

    @Override
    public AuthToken getAuthToken() {
        return authToken;
    }

    @Override
    public void clearAuthToken() {
        authToken = null;
    }

    // Validator overrides

    public static void validateId(int id) {
        if (id <= 0) {
            throw new NumberFormatException(
                "DbSessionImp id cannot be negative");
        }
    }
}
