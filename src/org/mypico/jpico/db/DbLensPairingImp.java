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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

import java.io.IOException;
import java.lang.reflect.Type;
import java.sql.SQLException;
import java.util.Date;
import java.util.Map;

import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.LensPairingImp;
import org.mypico.jpico.data.service.Service;

import java.util.List;


/**
 * A concrete {@link LensPairing} class which persists pairings to a database using ORMLite object
 * relational mapping annotations.
 *
 * @author Graeme Jenkinson &lt;gcj21@cam.ac.uk&gt;
 * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
 * @see LensPairing
 */
// Extends DbPairingImp only to get the same type as it.
@DatabaseTable(tableName = DbLensPairingImp.LENS_PAIRINGS_TABLE)
public class DbLensPairingImp implements LensPairingImp {

    private static final Gson CREDENTIALS_MAP_GSON = new Gson();
    private static final Type CREDENTIALS_MAP_TYPE =
        new TypeToken<Map<String, String>>() {
        }.getType();

    private static final Gson PRIVATE_FIELDS_GSON = new Gson();
    private static final Type PRIVATE_FIELDS_TYPE =
        new TypeToken<List<String>>() {
        }.getType();

    static final String LENS_PAIRINGS_TABLE = "lens_pairings";

    static final String ID_COLUMN = "id";
    static final String PAIRING_COLUMN = "pairing_id";
    static final String CREDENTIALS_STRING_COLUMN = "credentials_string";
    static final String PRIVATE_FIELDS_STRING_COLUMN = "private_fields_string";

    /**
     * Initial value of a DbCredentialPairingImp's id, before it is saved to the database.
     * DbCredentialPairingImps are automatically assigned an id when they are saved to the database
     * for the first time.
     */
    public static final int UNSAVED_CP_ID = 0;

    @DatabaseField(
        columnName = ID_COLUMN,
        generatedId = true, // Primary key -- automatically generated on save
        throwIfNull = true,
        useGetSet = true)
    private int cpId;

    @DatabaseField(
        columnName = PAIRING_COLUMN,
        foreign = true,
        foreignAutoRefresh = true,
        foreignAutoCreate = true,
        columnDefinition = "integer references pairings(\"id\") on delete cascade",
        canBeNull = false,
        useGetSet = true)
    private DbPairingImp dbPairing;

    @DatabaseField(
        columnName = CREDENTIALS_STRING_COLUMN,
        canBeNull = false,
        useGetSet = true)
    private String credentialsString;

    @DatabaseField(
        columnName = PRIVATE_FIELDS_STRING_COLUMN,
        canBeNull = false,
        useGetSet = true)
    private String privateFieldsString;

    private Dao<DbLensPairingImp, Integer> dao;

    static String jsonifyCredentials(final Map<String, String> credentials) {
        checkNotNull(credentials);
        return CREDENTIALS_MAP_GSON.toJson(
            credentials, CREDENTIALS_MAP_TYPE);
    }

    static Map<String, String> unjsonifyCredentials(final String credentialsString) {
        checkNotNull(credentialsString);
        return CREDENTIALS_MAP_GSON.fromJson(
            credentialsString, CREDENTIALS_MAP_TYPE);
    }

    static String jsonifyPrivateFields(final List<String> fields) {
        checkNotNull(fields);
        return PRIVATE_FIELDS_GSON.toJson(
            fields, PRIVATE_FIELDS_TYPE);
    }

    static List<String> unjsonifyPrivateFields(final String privateFieldsstring) {
        checkNotNull(privateFieldsstring);
        return PRIVATE_FIELDS_GSON.fromJson(
            privateFieldsstring, PRIVATE_FIELDS_TYPE);
    }

    /**
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public DbLensPairingImp() {
    }

    DbLensPairingImp(
        final String name,
        final DbServiceImp service,
        final Map<String, String> credentials,
        final List<String> privateFields,
        final Dao<DbPairingImp, Integer> pairingDao,
        final Dao<DbLensPairingImp, Integer> credentialPairingDao) {
        // Validate arguments (which are not validated by DbPairingImp)
        LensPairing.validateCredentials(credentials);

        this.cpId = UNSAVED_CP_ID;
        this.dbPairing = new DbPairingImp(name, service, pairingDao);
        this.credentialsString = jsonifyCredentials(credentials);
        this.privateFieldsString = jsonifyPrivateFields(privateFields);
        this.dao = credentialPairingDao;
    }

    void setDao(Dao<DbLensPairingImp, Integer> dao) {
        this.dao = dao;
    }

    @Override
    public void save() throws IOException {
        checkNotNull(
            dao, "DbCredentialPairingImp cannot be saved with null DAO");
        try {
            dao.createOrUpdate(this);
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public boolean isSaved() {
        return (cpId != UNSAVED_CP_ID && dbPairing.isSaved());
    }

    @Deprecated
    public void setCpId(int cpId) {
        this.cpId = cpId;
    }

    @Deprecated
    public int getCpId() {
        return cpId;
    }

    @Deprecated
    public void setDbPairing(DbPairingImp dbPairing) {
        assert (dbPairing != null);
        this.dbPairing = dbPairing;
    }

    @Deprecated
    public DbPairingImp getDbPairing() {
        return dbPairing;
    }

    @Deprecated
    public void setCredentialsString(String credentialsString) {
        // TODO validate
        this.credentialsString = credentialsString;
    }

    @Deprecated
    public String getCredentialsString() {
        return credentialsString;
    }

    public void setPrivateFieldsString(String privateFieldsString) {
        this.privateFieldsString = privateFieldsString;
    }

    public String getPrivateFieldsString() {
        return privateFieldsString;
    }

    @Override
    public int getId() {
        return dbPairing.getId();
    }

    @Override
    public Service getService() {
        return dbPairing.getService();
    }

    @Override
    public String getName() {
        return dbPairing.getName();
    }

    @Override
    public void setName(String newName) {
        dbPairing.setName(newName);
    }

    @Override
    public Date getDateCreated() {
        return dbPairing.getDateCreated();
    }

    @Override
    public Map<String, String> getCredentials() {
        return unjsonifyCredentials(credentialsString);
    }

    @Override
    public List<String> getPrivateFields() {
        return unjsonifyPrivateFields(privateFieldsString);
    }

    @Override
    public void delete() throws IOException {
        checkNotNull(dao, "cannot be saved with null dao");
        if (isSaved()) {
            try {
                dao.delete(this);
                cpId = UNSAVED_CP_ID;
            } catch (SQLException e) {
                throw new IOException(e);
            }
        } else {
            throw new IllegalStateException("cannot delete an unsaved pairing");
        }
    }
}
