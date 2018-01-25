package org.mypico.jpico.test.db;

import static org.junit.Assert.*;

import java.io.IOException;
import java.sql.SQLException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.mypico.jpico.db.DbTerminalAccessor;
import org.mypico.jpico.db.DbTerminalImp;
import org.mypico.jpico.db.DbTerminalImpFactory;
import org.mypico.jpico.db.DbVersioner;
import org.mypico.jpico.test.data.TestTerminalImpFactory;
import org.mypico.jpico.test.data.terminal.TerminalTest;
import org.mypico.jpico.test.util.DatabaseHelper;
import org.mypico.jpico.test.util.UsesCryptoTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.support.ConnectionSource;

public class DbVersionerTest extends UsesCryptoTest {
	private final static Logger LOGGER = LoggerFactory.getLogger(
			DbVersionerTest.class.getSimpleName());
	
	private static ConnectionSource dbConnection;
    private static DbTerminalImpFactory factory;
    private static DbTerminalAccessor accessor;
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        dbConnection = DatabaseHelper.getConnection();
        Dao<DbTerminalImp, Integer> terminalDao =
                DaoManager.createDao(dbConnection, DbTerminalImp.class);
        factory = new DbTerminalImpFactory(terminalDao);
        accessor = new DbTerminalAccessor(terminalDao);
    }
	
    @Test
    public void testDropDatabase() throws SQLException, IOException {
        DbVersioner.createDatabase(dbConnection); 
    	DbVersioner.dropDatabase(dbConnection);
    	
    	// If some exception happens here it means dropDatabase didn't delete all the tables
    	DbVersioner.createDatabase(dbConnection); 
    	
    	// Drop again so the next tests can use the thing correctly
    	DbVersioner.dropDatabase(dbConnection);
    }

    @Test
    public void testCreateTables() throws SQLException, IOException {
        DbTerminalImp imp = 
    			factory.getImp(TerminalTest.getTerminal(new TestTerminalImpFactory(), ""));
    	
    	try {
    		accessor.getTerminalById(imp.getId());
    		fail("Exception should be thrown if database is not created");
    	} catch (IOException e) {
    		
    	}
    	
       	DbVersioner.createDatabase(dbConnection); 
    	
    	assertNull("getTerminalById not null before save", accessor.getTerminalById(imp.getId()));
    	imp.save();
    	assertNotNull("getTerminalById null after save", accessor.getTerminalById(imp.getId()));
    	
    	DbVersioner.dropDatabase(dbConnection);
    }
    
    @Test
    public void testUpgradeFromCurrentVersionDoesNothing() throws SQLException, IOException {
        DbTerminalImp imp = 
    			factory.getImp(TerminalTest.getTerminal(new TestTerminalImpFactory(), ""));

       	DbVersioner.createDatabase(dbConnection); 
    	
    	assertNull("getTerminalById not null before save", accessor.getTerminalById(imp.getId()));
    	imp.save();
    	assertNotNull("getTerminalById null after save", accessor.getTerminalById(imp.getId()));
    	
    	DbVersioner.upgradeDatabase(dbConnection, DbVersioner.CURRENT_VERSION);
    	assertNotNull("getTerminalById null after save", accessor.getTerminalById(imp.getId()));
    	
    	DbVersioner.dropDatabase(dbConnection);
    }
    
    @Test
    public void testUpgradeBefore21DeletesDatabase() throws SQLException, IOException {
        DbTerminalImp imp = 
    			factory.getImp(TerminalTest.getTerminal(new TestTerminalImpFactory(), ""));

       	DbVersioner.createDatabase(dbConnection); 
    	
    	assertNull("getTerminalById not null before save", accessor.getTerminalById(imp.getId()));
    	imp.save();
    	assertNotNull("getTerminalById null after save", accessor.getTerminalById(imp.getId()));
    	
    	DbVersioner.upgradeDatabase(dbConnection, 10);
    	assertNull("getTerminalById not null before save", accessor.getTerminalById(imp.getId()));
    	
    	DbVersioner.dropDatabase(dbConnection);
    }
}
