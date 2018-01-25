package org.mypico.jpico.test.data;

import java.util.Map;

import org.mypico.jpico.data.pairing.LensPairingImp;
import org.mypico.jpico.data.service.Service;

import java.util.List;

public class TestLensPairingImp extends TestPairingImp implements
        LensPairingImp {

    private Map<String, String> credentials;
	private List<String> privateFields;

    TestLensPairingImp(
            String name,
            Service service,
            Map<String, String> credentials,
			List<String> privateFields) {
        super(name, service);
        this.credentials = credentials;
		this.privateFields = privateFields;
    }

    @Override
    public Map<String, String> getCredentials() {
        return credentials;
    }
    
	@Override
	public List<String> getPrivateFields() {
        return privateFields;
    }

}
