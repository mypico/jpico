package org.mypico.jpico.test.data;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;
import java.util.List;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.DataFactory;
import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.pairing.KeyPairingImp;
import org.mypico.jpico.data.pairing.KeyPairingImpFactory;
import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.LensPairingImp;
import org.mypico.jpico.data.pairing.LensPairingImpFactory;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingImp;
import org.mypico.jpico.data.pairing.PairingImpFactory;
import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImp;
import org.mypico.jpico.data.service.ServiceImpFactory;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImp;
import org.mypico.jpico.data.session.SessionImpFactory;
import org.mypico.jpico.data.session.Session.Error;
import org.mypico.jpico.data.session.Session.Status;
import org.mypico.jpico.data.terminal.Terminal;
import org.mypico.jpico.data.terminal.Terminal.Imp;

public class TestDataFactory implements DataFactory {

    private ServiceImpFactory sf = new TestServiceImpFactory();
    private PairingImpFactory pf = new TestPairingImpFactory();
    private KeyPairingImpFactory kpf = new TestKeyPairingImpFactory();
    private LensPairingImpFactory cpf = new TestLensPairingImpFactory();
    private SessionImpFactory snf = new TestSessionImpFactory();
    private Terminal.ImpFactory tf = new TestTerminalImpFactory();

    @Override
    public ServiceImp getImp(String name, URI address, byte[] commitment) {
        return sf.getImp(name, address, commitment);
    }

    @Override
    public ServiceImp getImp(Service service) {
        return sf.getImp(service);
    }

    @Override
    public PairingImp getImp(String name, Service service) {
        return pf.getImp(name, service);
    }

    @Override
    public PairingImp getImp(Pairing pairing) {
        return pf.getImp(pairing);
    }

    @Override
    public KeyPairingImp getImp(
            String name,
            Service service,
            PublicKey publicKey,
            PrivateKey privateKey,
            String extraData) {
        return kpf.getImp(name, service, publicKey, privateKey, extraData);
    }

    @Override
    public KeyPairingImp getImp(String name, Service service, KeyPair keyPair, String extraData) {
        return kpf.getImp(name, service, keyPair, extraData);
    }

    @Override
    public KeyPairingImp getImp(KeyPairing keyPairing) {
        return kpf.getImp(keyPairing);
    }

    @Override
    public LensPairingImp getImp(
            String name,
            Service service,
            Map<String, String> credentials,
			List<String> privateFields) {
        return cpf.getImp(name, service, credentials, privateFields);
    }

    @Override
    public LensPairingImp getImp(LensPairing lensPairing) {
        return cpf.getImp(lensPairing);
    }

    @Override
    public SessionImp getImp(
            String remoteId,
            SecretKey secretKey,
            Pairing pairing,
            AuthToken authToken,
            Date lastAuthDate,
            Status status,
            Error error) {
        return snf.getImp(remoteId, secretKey, pairing, authToken, lastAuthDate, status, error);
    }

    @Override
    public SessionImp getImp(Session session) {
        return snf.getImp(session);
    }

	@Override
	public Imp getImp(
			String name, byte[] commitment, PublicKey picoPublicKey, PrivateKey picoPrivateKey) {
		return tf.getImp(name, commitment, picoPublicKey, picoPrivateKey);
	}

	@Override
	public Imp getImp(Terminal terminal) {
		return tf.getImp(terminal);
	}

}
