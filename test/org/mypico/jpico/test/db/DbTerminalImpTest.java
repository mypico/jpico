package org.mypico.jpico.test.db;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mypico.jpico.db.DbTerminalAccessor;
import org.mypico.jpico.db.DbTerminalImp;
import org.mypico.jpico.db.DbTerminalImpFactory;
import org.mypico.jpico.test.data.TestTerminalImpFactory;
import org.mypico.jpico.test.data.terminal.TerminalTest;
import org.mypico.jpico.test.util.DatabaseHelper;
import org.mypico.jpico.test.util.UsesCryptoTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;

public class DbTerminalImpTest extends UsesCryptoTest {

	private final static Logger LOGGER = LoggerFactory.getLogger(
            DbServiceAccessorTest.class.getSimpleName());

    private static ConnectionSource dbConnection;
    private static DbTerminalImpFactory factory;
    private static DbTerminalAccessor accessor;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        // Get a connection to the database
        LOGGER.debug("Connecting to the database...");
        dbConnection = DatabaseHelper.getConnection();
        LOGGER.info("Connected to database");

        Dao<DbTerminalImp, Integer> terminalDao =
                DaoManager.createDao(dbConnection, DbTerminalImp.class);
        factory = new DbTerminalImpFactory(terminalDao);
        accessor = new DbTerminalAccessor(terminalDao);
    }

    @Before
    public void setUp() throws Exception {
        // Create database tables
        LOGGER.debug("Creating database tables...");
        TableUtils.createTable(dbConnection, DbTerminalImp.class);
        LOGGER.info("Database tables created");
    }

    @After
    public void tearDown() throws Exception {
        // Delete database tables
        LOGGER.debug("Deleting database tables...");
        TableUtils.dropTable(dbConnection, DbTerminalImp.class, true);
        LOGGER.info("Database tables deleted");
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        // Close database connection
        LOGGER.debug("Closing database connection");
        dbConnection.close();
        LOGGER.info("Closed database connection");
    }

    @Test
    public void testSaveDelete() throws IOException {
    	DbTerminalImp imp = 
    			factory.getImp(TerminalTest.getTerminal(new TestTerminalImpFactory(), ""));
    	
    	assertNull("getTerminalById not null before save", accessor.getTerminalById(imp.getId()));
    	assertFalse("isSaved true before save", imp.isSaved());
    	
    	imp.save();
    	
    	assertNotNull("getTerminalById null after save", accessor.getTerminalById(imp.getId()));
    	assertTrue("isSaved false after save", imp.isSaved());
    	
    	imp.delete();
    	
    	assertNull("getTerminalById not null after delete", accessor.getTerminalById(imp.getId()));
    	assertFalse("isSaved true after delete", imp.isSaved());
    }
}
