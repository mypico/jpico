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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.SQLException;
import java.util.Date;

import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.pairing.KeyPairingImp;
import org.mypico.jpico.data.service.Service;

import com.google.common.base.Preconditions;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * A concrete {@link KeyPairing} class which persists pairings to a database using ORMLite object
 * relational mapping annotations. Public and private key fields are persisted using custom
 * persister classes.
 *
 * @author Graeme Jenkinson &lt;gcj21@cam.ac.uk&gt;
 * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
 * @see KeyPairing
 * @see PrivateKeyPersister
 * @see PublicKeyPersister
 */
// Extends DbPairingImp only to get the same type as it.
@DatabaseTable(tableName = DbKeyPairingImp.KEY_PAIRINGS_TABLE)
public class DbKeyPairingImp implements KeyPairingImp {

    static final String KEY_PAIRINGS_TABLE = "key_pairings";

    static final String ID_COLUMN = "id";
    static final String PAIRING_COLUMN = "pairing_id";
    static final String PRIVATE_KEY_COLUMN = "private_key";
    static final String PUBLIC_KEY_COLUMN = "public_key";
    static final String EXTRA_DATA_COLUMN = "extra_data";

    /**
     * Initial value of a DbKeyPairingImp's id, before it is saved to the database. DbPairingImps
     * are automatically assigned an id when they are saved to the database for the first time.
     */
    public static final int UNSAVED_KP_ID = 0;

    @DatabaseField(
        columnName = ID_COLUMN,
        generatedId = true, // Primary key -- automatically generated on save
        throwIfNull = true,
        useGetSet = true)
    private int kpId;

    @DatabaseField(
        columnName = PAIRING_COLUMN,
        foreign = true,
        foreignAutoRefresh = true,
        foreignAutoCreate = true,
        columnDefinition = "integer references pairings(\"id\") on delete cascade",
        canBeNull = false,
        useGetSet = true
    )
    private DbPairingImp dbPairing;

    @DatabaseField(
        columnName = PRIVATE_KEY_COLUMN,
        canBeNull = false,
        useGetSet = true,
        persisterClass = PrivateKeyPersister.class)
    private PrivateKey privateKey;

    @DatabaseField(
        columnName = PUBLIC_KEY_COLUMN,
        canBeNull = false,
        useGetSet = true,
        persisterClass = PublicKeyPersister.class)
    private PublicKey publicKey;

    @DatabaseField(
        columnName = EXTRA_DATA_COLUMN,
        canBeNull = true,
        useGetSet = true)
    private String extraData;

    private Dao<DbKeyPairingImp, Integer> dao;

    /**
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public DbKeyPairingImp() {
    }

    DbKeyPairingImp(
        final String name,
        final DbServiceImp service,
        final PublicKey publicKey,
        final PrivateKey privateKey,
        final String extraData,
        final Dao<DbPairingImp, Integer> pairingDao,
        final Dao<DbKeyPairingImp, Integer> keyPairingDao) {
        this.kpId = UNSAVED_KP_ID;
        this.dbPairing = new DbPairingImp(name, service, pairingDao);
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.extraData = extraData;
        this.dao = keyPairingDao;
    }

    void setDao(Dao<DbKeyPairingImp, Integer> dao) {
        this.dao = dao;
    }

    @Override
    public void save() throws IOException {
        Preconditions.checkNotNull(
            dao, "DbKeyPairingImp cannot be saved with null DAO");
        try {
            dao.createOrUpdate(this);
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public boolean isSaved() {
        return (kpId != UNSAVED_KP_ID && dbPairing.isSaved());
    }

    @Deprecated
    public void setKpId(int kpId) {
        this.kpId = kpId;
    }

    @Deprecated
    public int getKpId() {
        return kpId;
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

    @Deprecated
    public void setDbPairing(DbPairingImp dbPairing) {
        assert (dbPairing != null);
        this.dbPairing = dbPairing;
    }

    @Deprecated
    public DbPairingImp getDbPairing() {
        return dbPairing;
    }

    /**
     * @param publicKey new public key value for this DbPairing.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setPublicKey(final PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * @param privateKey new private key value for this DbPairing.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setPrivateKey(final PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public String getExtraData() {
        return extraData;
    }

    public void setExtraData(String extraData) {
        this.extraData = extraData;
    }


    @Override
    public void delete() throws IOException {
        checkNotNull(dao, "cannot be saved with null dao");
        if (isSaved()) {
            try {
                dao.delete(this);
                kpId = UNSAVED_KP_ID;
            } catch (SQLException e) {
                throw new IOException(e);
            }
        } else {
            throw new IllegalStateException("cannot delete an unsaved pairing");
        }
    }
}
