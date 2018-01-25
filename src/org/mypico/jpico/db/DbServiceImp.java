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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.sql.SQLException;

import org.mypico.jpico.comms.org.apache.commons.codec.binary.Base64;
import org.mypico.jpico.crypto.CryptoRuntimeException;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImp;

import com.google.common.base.Preconditions;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * A concrete {@link Service} class which persists services to a database using ORMLite object
 * relational mapping annotations. Public key fields are persisted using a custom persister class.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see Service
 * @see PublicKeyPersister
 */
@DatabaseTable(tableName = DbServiceImp.SERVICES_TABLE)
public class DbServiceImp implements ServiceImp {

    static final String SERVICES_TABLE = "services";

    static final String ID_COLUMN = "id";
    static final String NAME_COLUMN = "name";
    static final String ADDRESS_STRING_COLUMN = "address";
    static final String COMMITMENT_COLUMN = "commitment";

    /**
     * Initial value of a DbServiceImp's id, before it is saved to the database. DbServiceImps are
     * automatically assigned an id when they are saved to the database for the first time.
     */
    public static final int UNSAVED_ID = 0;

    static String stringifyCommitment(byte[] commitment) {
        return Base64.encodeBase64String(commitment);
    }

    static byte[] unstringifyCommitment(String commitmentString) {
        return Base64.decodeBase64(commitmentString);
    }

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
        columnName = ADDRESS_STRING_COLUMN,
        canBeNull = false,
        useGetSet = true)
    private String addressString;

    @DatabaseField(
        columnName = COMMITMENT_COLUMN,
        index = true,
        canBeNull = false,
        useGetSet = true)
    private String commitmentString;

    private Dao<DbServiceImp, Integer> dao;

    /**
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public DbServiceImp() {
    }

    DbServiceImp(
        final String name,
        final URI address,
        final byte[] commitment,
        final Dao<DbServiceImp, Integer> dao) {
        this.id = UNSAVED_ID;
        this.name = name;
        this.addressString = address.toString();
        this.commitmentString = stringifyCommitment(commitment);
        this.dao = Preconditions.checkNotNull(
            dao, "Cannot construct DbServiceImp with null dao");
    }

    void setDao(final Dao<DbServiceImp, Integer> dao) {
        this.dao = Preconditions.checkNotNull(
            dao, "Cannot set dao to null");
    }

    @Override
    public void save() throws IOException {
        Preconditions.checkNotNull(
            dao, "DbServiceImp cannot be saved with null DAO");
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
     * @param id new id value for this <code>DbServiceImp</code>.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setId(final int id) {
        DbServiceImp.checkId(id);
        this.id = id;
    }

    /**
     * Return the id of this <code>DbServiceImp</code>. The id of a <code>DbServiceImp</code>Imp is
     * automatically assigned when it is first saved to the database. This id (see
     * {@link #ID_COLUMN ID_COLUMN}) is the primary key in the services database table.
     *
     * @return id of this <code>DbServiceImp</code>.
     * @see DbServiceImp#UNSAVED_ID
     */
    @Override
    public int getId() {
        return id;
    }

    /**
     * @param name new name value for this <code>DbServiceImp</code>.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setName(final String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    /**
     * Set the address to use for the service.
     *
     * @param addressString The service address.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setAddressString(final String addressString) {
        this.addressString = addressString;
    }

    /**
     * Get the address currently in use for the service.
     *
     * @return The service address.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public String getAddressString() {
        return addressString;
    }

    @Override
    public void setAddress(URI address) {
        this.addressString = address.toString();
    }

    @Override
    public URI getAddress() {
        try {
            return new URI(addressString);
        } catch (URISyntaxException e) {
            // Should never happen because addressString should only ever be
            // set in the constructor or in setAddress from URI.toString()
            throw new RuntimeException("addressString not a valid URI", e);
        }
    }

    /**
     * Set the commitment for the service.
     *
     * @param commitmentString The commitment of the service.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public void setCommitmentString(final String commitmentString) {
        this.commitmentString = commitmentString;
    }

    /**
     * Get the service commitment.
     *
     * @return The service commitment.
     * @deprecated required by ORMLite, but should not be used.
     */
    @Deprecated
    public String getCommitmentString() {
        return commitmentString;
    }

    @Override
    public byte[] getCommitment() {
        return unstringifyCommitment(commitmentString);
    }

    /**
     * Get the commitment of a public key using the SHA256 digest algorithm. The output byte array
     * is converted to hexadecimal String.
     *
     * @param publicKey to return the commitment of.
     * @return SHA256 hash of the public key encoded as a hexdecimal String.
     */
    @Deprecated
    static String getCommitment(final PublicKey publicKey) {
        Preconditions.checkNotNull(publicKey);
        try {
            // Generate a hash of the public key to index the Pairings
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(publicKey.getEncoded());

            byte byteData[] = md.digest();

            // Convert the byte to hex format
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {

                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoRuntimeException(e);
        }
    }

    // Database-specific argument checks:

    public static int checkId(int id) {
        if (id <= 0) {
            throw new NumberFormatException(
                "DbServiceImp id cannot be negative");
        }
        return id;
    }
}
