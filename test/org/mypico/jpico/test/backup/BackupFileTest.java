package org.mypico.jpico.test.backup;

import org.junit.Test;
import org.mypico.jpico.backup.BackupFile;
import org.mypico.jpico.backup.BackupFileDecryptionException;
import org.mypico.jpico.backup.BackupKey;
import org.mypico.jpico.backup.BackupKeyInvalidException;
import org.mypico.jpico.backup.BackupKeyInvalidLengthException;
import org.mypico.jpico.backup.EncBackupFile;
import org.mypico.jpico.test.util.UsesCryptoTest;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

public class BackupFileTest extends UsesCryptoTest {
	public static class ConcreteBackupKey extends BackupKey {
		private ConcreteBackupKey() {
			super();
		}
		
		private ConcreteBackupKey(byte[] bytes) throws BackupKeyInvalidLengthException {
			super(bytes);
		}
		
		public static ConcreteBackupKey newInstance(byte[] bytes) throws BackupKeyInvalidLengthException {
			if (bytes == null) {
				return new ConcreteBackupKey();
			} else {
				return new ConcreteBackupKey(bytes);		
			}
		}
	}
	
	@Test
	public void randomKeyEncDecTest() throws IOException, BackupKeyInvalidException, BackupFileDecryptionException {
		File tempFile = File.createTempFile("database", ".db");
		Files.write(new String("Data writing to file").getBytes("utf-8"), tempFile);
		
		// Just for sanity
		List<String> lines = Files.readLines(tempFile, Charsets.UTF_8);
		assertEquals(lines.size(), 1);
		assertEquals(lines.get(0), "Data writing to file");
		
		
		BackupFile backupFile = BackupFile.newInstance(tempFile);
		BackupKey backupKey = null;
		try {
			backupKey = ConcreteBackupKey.newInstance(null);
		} catch (BackupKeyInvalidLengthException e) {
			// This is unexpected to happen as the constructor for
			// BackupKey should generate a key in the right size
			e.printStackTrace();
			fail();
		}
		
		assertNotNull(backupKey);
		
		EncBackupFile encryptedFile = backupFile.createEncBackupFile(backupKey);
		
		BackupFile restored = encryptedFile.createUnencryptedBackupFile(File.createTempFile("restored", ".db"), backupKey);
		
		List<String> linesRestored = Files.readLines(restored.getDbFile(), Charsets.UTF_8);
		assertEquals(linesRestored.size(), 1);
		assertEquals(linesRestored.get(0), "Data writing to file");
	}
	
	@Test
	public void wrongKeySize() {
		try {
			ConcreteBackupKey.newInstance(new byte[]{0x00, 0x01, 0x02, 0x03});
			fail();
		} catch (BackupKeyInvalidLengthException e) {
		}
	}
	
	@Test
	public void wrongKeyDecryption() throws IOException, BackupKeyInvalidLengthException, BackupKeyInvalidException {
		File tempFile = File.createTempFile("database", ".db");
		Files.write(new String("Data writing to file").getBytes("utf-8"), tempFile);
		BackupFile backupFile = BackupFile.newInstance(tempFile);
		BackupKey backupKey = ConcreteBackupKey.newInstance(null);
		
		assertNotNull(backupKey);
		
		EncBackupFile encryptedFile = backupFile.createEncBackupFile(backupKey);
		
		BackupKey wrongKey = ConcreteBackupKey.newInstance(null);
		try {
			encryptedFile.createUnencryptedBackupFile(File.createTempFile("restored", ".db"), wrongKey);
			fail();
		} catch (BackupFileDecryptionException e) {
		}
	}
	
	@Test
	public void wrongCiphertext() throws IOException, BackupKeyInvalidLengthException, BackupKeyInvalidException {
		File tempFile = File.createTempFile("database", ".db");
		Files.write(new String("Data writing to file").getBytes("utf-8"), tempFile);
		BackupFile backupFile = BackupFile.newInstance(tempFile);
		BackupKey backupKey = ConcreteBackupKey.newInstance(null);
		
		assertNotNull(backupKey);
		
		EncBackupFile encryptedFile = backupFile.createEncBackupFile(backupKey);
		encryptedFile.getEncryptedData()[0] ^= 0xff;
		
		try {
			encryptedFile.createUnencryptedBackupFile(File.createTempFile("restored", ".db"), backupKey);
			fail();
		} catch (BackupFileDecryptionException e) {
		}
	}
}
