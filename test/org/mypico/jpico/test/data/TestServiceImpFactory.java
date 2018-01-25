package org.mypico.jpico.test.data;

import java.net.URI;

import org.mypico.jpico.data.service.Service;
import org.mypico.jpico.data.service.ServiceImp;
import org.mypico.jpico.data.service.ServiceImpFactory;

public class TestServiceImpFactory implements ServiceImpFactory {

    @Override
    public ServiceImp getImp(String name, URI address, byte[] commitment) {
        return new TestServiceImp(name, address, commitment);
    }

    @Override
    public ServiceImp getImp(Service service) {
        return getImp(
                service.getName(),
                service.getAddress(),
                service.getCommitment());
    }

}
