package org.mypico.jpico.test.db;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mypico.jpico.data.terminal.Terminal.Accessor;
import org.mypico.jpico.data.terminal.Terminal.ImpFactory;
import org.mypico.jpico.db.DbTerminalAccessor;
import org.mypico.jpico.db.DbTerminalImp;
import org.mypico.jpico.db.DbTerminalImpFactory;
import org.mypico.jpico.test.data.terminal.TerminalAccessorTest;
import org.mypico.jpico.test.util.DatabaseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;

public class DbTerminalAccessorTest extends TerminalAccessorTest {

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
    @Override
    public void setUp() throws Exception {
        super.setUp();

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
	
	@Override
	protected ImpFactory getFactory() {
		return factory;
	}

	@Override
	protected Accessor getAccessor() {
		return accessor;
	}

}
