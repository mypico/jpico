package org.mypico.jpico.test.data;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.pairing.KeyPairingImp;
import org.mypico.jpico.data.pairing.KeyPairingImpFactory;
import org.mypico.jpico.data.service.Service;

public class TestKeyPairingImpFactory implements KeyPairingImpFactory {

    @Override
    public KeyPairingImp getImp(
            String name,
            Service service,
            PublicKey publicKey,
            PrivateKey privateKey,
            String extraData) {
        return new TestKeyPairingImp(name, service, publicKey, privateKey, extraData);
    }

    @Override
    public KeyPairingImp getImp(String name, Service service, KeyPair keyPair, String extraData) {
        return getImp(
                name, service, keyPair.getPublic(), keyPair.getPrivate(), extraData);
    }

    @Override
    public KeyPairingImp getImp(KeyPairing keyPairing) {
        return getImp(
                keyPairing.getName(),
                keyPairing.getService(),
                keyPairing.getPublicKey(),
                keyPairing.getPrivateKey(),
                keyPairing.getExtraData());
    }

}
