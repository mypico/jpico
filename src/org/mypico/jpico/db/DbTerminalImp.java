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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.SQLException;

import org.mypico.jpico.data.terminal.Terminal;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * A concrete {@link Terminal} class which persists terminals to a database using ORMLite object
 * relational mapping annotations. Public key fields are persisted using a custom persister class.
 *
 * @see Terminal
 * @see PublicKeyPersister
 */
@DatabaseTable(tableName = DbTerminalImp.TERMINALS_TABLE)
public class DbTerminalImp implements Terminal.Imp {

    public static final String TERMINALS_TABLE = "terminals";

    public static final String ID_COLUMN = "id";
    static final String NAME_COLUMN = "name";
    static final String COMMITMENT_COLUMN = "commitment";
    static final String PICO_PUBLIC_KEY_COLUMN = "pico_public_key";
    static final String PICO_PRIVATE_KEY_COLUMN = "pico_private_key";

    /**
     * Initial value of an instance's id, before it is saved to the database.
     * They will automatically be assigned a different unique id when they are
     * saved to the database for the first time.
     */
    public static final int UNSAVED_ID = 0;

    @DatabaseField(
        columnName = ID_COLUMN,
        generatedId = true, // Primary key -- automatically generated on save
        throwIfNull = true,
        useGetSet = true)
    private int id;

    @DatabaseField(
        columnName = NAME_COLUMN,
        canBeNull = false,
        useGetSet = true)
    private String name;

    @DatabaseField(
        columnName = COMMITMENT_COLUMN,
        index = true,
        canBeNull = false,
        useGetSet = true)
    private String commitmentString;

    @DatabaseField(
        columnName = PICO_PUBLIC_KEY_COLUMN,
        canBeNull = false,
        useGetSet = true,
        persisterClass = PublicKeyPersister.class)
    private PublicKey picoPublicKey;

    @DatabaseField(
        columnName = PICO_PRIVATE_KEY_COLUMN,
        canBeNull = false,
        useGetSet = true,
        persisterClass = PrivateKeyPersister.class)
    private PrivateKey picoPrivateKey;

    private Dao<DbTerminalImp, Integer> dao;

    /**
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public DbTerminalImp() {
    }

    DbTerminalImp(
        final String name,
        final byte[] commitment,
        final PublicKey picoPublicKey,
        final PrivateKey picoPrivateKey,
        final Dao<DbTerminalImp, Integer> dao) {
        this.id = UNSAVED_ID;
        this.name = name;
        this.commitmentString = DbServiceImp.stringifyCommitment(commitment);
        this.picoPublicKey = picoPublicKey;
        this.picoPrivateKey = picoPrivateKey;
        this.dao = checkNotNull(dao, "dao cannot be null");
    }

    void setDao(final Dao<DbTerminalImp, Integer> dao) {
        this.dao = checkNotNull(dao, "dao cannot be null");
    }

    @Override
    public void save() throws IOException {
        checkNotNull(dao, "cannot be saved with null dao");
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
            throw new IllegalStateException("cannot delete an unsaved terminal");
        }
    }

    /**
     * Set the id of the terminal.
     *
     * @param id The ide of the terminal.
     * @deprecated Required by ORMLite, should not be used.
     */
    @Deprecated
    public void setId(int id) {
        this.id = id;
    }

    /**
     * Get the id of the terminal.
     *
     * @return The terminal id.
     */
    @Override
    public int getId() {
        return id;
    }

    /**
     * Set the name of the terminal.
     *
     * @param name The name of the terminal.
     * @deprecated Required by ORMLite, should not be used.
     */
    @Deprecated
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the name of the terminal.
     *
     * @return The name of the terminal.
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * Set the commitment for the terminal.
     *
     * @param commitmentString The terminal commitment.
     * @deprecated Required by ORMLite, should not be used.
     */
    @Deprecated
    public void setCommitmentString(String commitmentString) {
        this.commitmentString = commitmentString;
    }

    /**
     * Get the terminal commitment as a string.
     *
     * @return The terminal commitment.
     * @deprecated Required by ORMLite, should not be used.
     */
    @Deprecated
    public String getCommitmentString() {
        return commitmentString;
    }

    /**
     * Get the terminal commitment as a byte array.
     *
     * @return The terminal commitment.
     */
    @Override
    public byte[] getCommitment() {
        return DbServiceImp.unstringifyCommitment(commitmentString);
    }

    /**
     * Set the public key of the terminal.
     *
     * @param picoPublicKey The terminal public key.
     * @deprecated Required by ORMLite, should not be used.
     */
    @Deprecated
    public void setPicoPublicKey(PublicKey picoPublicKey) {
        this.picoPublicKey = picoPublicKey;
    }

    /**
     * Get the public key of the terminal.
     *
     * @return The terminal public key.
     */
    @Override
    public PublicKey getPicoPublicKey() {
        return picoPublicKey;
    }

    /**
     * Set the private key of the terminal.
     *
     * @param picoPrivateKey The terminal private key.
     * @deprecated Required by ORMLite, should not be used.
     */
    @Deprecated
    public void setPicoPrivateKey(PrivateKey picoPrivateKey) {
        this.picoPrivateKey = picoPrivateKey;
    }

    /**
     * Get the private key of the terminal.
     *
     * @return The terminal private key.
     */
    @Override
    public PrivateKey getPicoPrivateKey() {
        return picoPrivateKey;
    }
}
