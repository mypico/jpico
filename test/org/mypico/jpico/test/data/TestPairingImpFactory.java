package org.mypico.jpico.test.data;

import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.pairing.PairingImp;
import org.mypico.jpico.data.pairing.PairingImpFactory;
import org.mypico.jpico.data.service.Service;

public class TestPairingImpFactory implements PairingImpFactory {

    @Override
    public PairingImp getImp(String name, Service service) {
        return new TestPairingImp(name, service);
    }

    @Override
    public PairingImp getImp(Pairing pairing) {
        return getImp(pairing.getName(), pairing.getService());
    }

}
