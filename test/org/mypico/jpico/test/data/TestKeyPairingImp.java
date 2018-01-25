package org.mypico.jpico.test.data;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.mypico.jpico.data.pairing.KeyPairingImp;
import org.mypico.jpico.data.service.Service;

public class TestKeyPairingImp extends TestPairingImp implements
        KeyPairingImp {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String extraData;

    TestKeyPairingImp(
            String name,
            Service service,
            PublicKey publicKey,
            PrivateKey privateKey,
            String extraData) {
        super(name, service);
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

	@Override
	public String getExtraData() {
		return extraData;
	}

}
