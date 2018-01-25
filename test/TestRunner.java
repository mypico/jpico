import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class TestRunner {
	public static void main(String[] args) {
		Result result = JUnitCore.runClasses(
			org.mypico.rendezvous.test.RendezvousChannelTest.class,
			org.mypico.jpico.test.backup.BackupFileTest.class, 
			org.mypico.jpico.test.visualcode.NewKeyVisualCodeTest.class, 
			org.mypico.jpico.test.visualcode.KeyPairingVisualCodeTest.class,
			org.mypico.jpico.test.crypto.AuthenticationTest.class,
			org.mypico.jpico.test.gson.PublicKeyGsonSerializerTest.class,
			org.mypico.jpico.test.db.DbTerminalAccessorTest.class,
			org.mypico.jpico.test.db.DbKeyPairingAccessorTest.class,
			org.mypico.jpico.test.db.DbPairingAccessorTest.class,
			org.mypico.jpico.test.db.DbVersionerTest.class,
			org.mypico.jpico.test.crypto.ContinuousAuthTest.class,
			org.mypico.jpico.test.crypto.messages.SequenceNumberTest.class,
			org.mypico.jpico.test.gson.NonceGsonTest.class,
			org.mypico.jpico.test.db.DbTerminalImpTest.class,
			org.mypico.jpico.test.data.pairing.KeyPairingTest.class,
			org.mypico.jpico.test.data.service.ServiceTest.class,
			org.mypico.jpico.test.crypto.messages.PicoReauthMessageTest.class,
			org.mypico.jpico.test.data.pairing.PairingTest.class,
			org.mypico.jpico.test.crypto.SimpleAuthTokenTest.class,
			org.mypico.jpico.test.crypto.messages.ServiceReauthMessageTest.class,
			org.mypico.jpico.test.db.DbServiceAccessorTest.class,
			org.mypico.jpico.test.gson.MessageGsonTest.class,
			org.mypico.jpico.test.gson.ByteArrayGsonSerializerTest.class,
			org.mypico.jpico.test.data.session.SessionTest.class,
			org.mypico.jpico.test.crypto.messages.ServiceAuthMessageTest.class,
			org.mypico.jpico.test.crypto.messages.PicoAuthMessageTest.class,
			org.mypico.jpico.test.data.pairing.LensPairingTest.class,
			org.mypico.jpico.test.crypto.messages.ReauthStateTest.class,
			org.mypico.jpico.test.crypto.BrowserAuthTokenTest.class,
			org.mypico.jpico.test.db.DbLensPairingAccessorTest.class,
			org.mypico.jpico.test.visualcode.VisualCodeTestSuite.class,
			org.mypico.jpico.test.visualcode.NewKeyVisualCodeTest.class,
			org.mypico.jpico.test.visualcode.KeyPairingVisualCodeTest.class,
			org.mypico.jpico.test.gson.VisualCodeGsonTest.class,
			org.mypico.jpico.test.crypto.CookieTest.class,
			org.mypico.jpico.test.gson.VisualCodeGsonTest.class, 
			org.mypico.jpico.test.util.PicoCookieManagerTest.class 
		);
 		
		for (Failure failure : result.getFailures()) {
			System.out.println(failure.toString());
			System.out.println(failure.getDescription().toString());
		}
  		
		System.out.println(result.wasSuccessful());

        System.exit(result.wasSuccessful() ? 0 : -1);
    }
}  	
