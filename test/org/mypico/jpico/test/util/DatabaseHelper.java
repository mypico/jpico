package org.mypico.jpico.test.util;

import java.sql.SQLException;

import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;

public class DatabaseHelper {

    private final static String DB_PROTOCOL = "jdbc:derby:";
    private final static String DB_NAME = "derbyDB";

    public static ConnectionSource getConnection() throws SQLException {
        return new JdbcConnectionSource(DB_PROTOCOL + DB_NAME + ";create=true");
    }
}
