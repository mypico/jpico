package org.mypico.jpico.test.data;

import java.util.Map;

import org.mypico.jpico.data.pairing.LensPairing;
import org.mypico.jpico.data.pairing.LensPairingImp;
import org.mypico.jpico.data.pairing.LensPairingImpFactory;
import org.mypico.jpico.data.service.Service;

import java.util.List;

public class TestLensPairingImpFactory implements
        LensPairingImpFactory {

    @Override
    public LensPairingImp getImp(
            String name,
            Service service,
            Map<String, String> credentials,
			List<String> privateFields) {
        return new TestLensPairingImp(name, service, credentials, privateFields);
    }

    @Override
    public LensPairingImp getImp(LensPairing credentialPairing) {
        return getImp(
                credentialPairing.getName(),
                credentialPairing.getService(),
                credentialPairing.getCredentials(),
				credentialPairing.getPrivateFields());
    }

}
