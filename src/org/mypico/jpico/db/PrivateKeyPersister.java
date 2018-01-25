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

import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.field.types.BaseDataType;
import com.j256.ormlite.misc.SqlExceptionUtil;
import com.j256.ormlite.support.DatabaseResults;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.SQLException;

/**
 * A custom ORMLite persister for PrivateKey instances. Persists a Elliptic Curve key to the
 * database. The key is stored as a PKCS8 encoded byte array.
 *
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see PublicKeyPersister
 */
public class PrivateKeyPersister extends BaseDataType {

    private static final PrivateKeyPersister singleton = new PrivateKeyPersister();

    public static PrivateKeyPersister getSingleton() {
        return singleton;
    }

    protected PrivateKeyPersister() {
        super(SqlType.BYTE_ARRAY, new Class<?>[0]);
    }

    protected PrivateKeyPersister(SqlType sqlType, Class<?>[] classes) {
        super(sqlType, classes);
    }

    /**
     * Set a PrivateKey field to a default value.
     *
     * @param fieldType  The field type (BYTE_ARRAY).
     * @param defaultStr The request default value.
     * @return Object default representation.
     * @throws SQLException PrivateKey cannot have a default value.
     */
    @Override
    public Object parseDefaultString(FieldType fieldType, String defaultStr) throws SQLException {
        throw new SQLException("PrivateKey cannot have a default value");
    }

    /**
     * Convert a result of an SQL query into the type of class as the data is persisted in the
     * database.
     *
     * @param fieldType The field type (BYTE_ARRAY).
     * @param results   The result from an SQL query.
     * @param columnPos The column index.
     * @return byte[] of the PKCS8 encoded private key.
     */
    @Override
    public Object resultToSqlArg(FieldType fieldType, DatabaseResults results, int columnPos)
        throws SQLException {
        return results.getBytes(columnPos);
    }

    /**
     * Convert a persisted byte array into a PrivateKey instance.
     *
     * @param fieldType The field type (BYTE_ARRAY).
     * @param sqlArg    The type of the class as it is persisted in the databases.
     * @param columnPos The column index.
     * @return a PrivateKey instance.
     * @throws SQLException TODO
     */
    @Override
    public Object sqlArgToJava(FieldType fieldType, Object sqlArg, int columnPos)
        throws SQLException {
        try {
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(
                new PKCS8EncodedKeySpec((byte[]) sqlArg));
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw SqlExceptionUtil.create("No such algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw SqlExceptionUtil.create("Invalid key spec", e);
        }
    }

    /**
     * Convert a PrivateKey instance to a byte array for persisting.
     *
     * @param fieldType  The field type (BYTE_ARRAY).
     * @param javaObject The POJO Java object, that is, a PrivateKey.
     * @return byte[] PKCS8 encoded private key.
     */
    @Override
    public Object javaToSqlArg(FieldType fieldType, Object javaObject) {
        PrivateKey privateKey = (PrivateKey) javaObject;
        return privateKey.getEncoded();
    }

    @Override
    public boolean isAppropriateId() {
        return false;
    }

    @Override
    public boolean isArgumentHolderRequired() {
        return true;
    }

}

// End of file
