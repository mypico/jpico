package org.mypico.jpico.test.data;

import java.util.Date;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImp;
import org.mypico.jpico.data.session.SessionImpFactory;
import org.mypico.jpico.data.session.Session.Error;
import org.mypico.jpico.data.session.Session.Status;

public class TestSessionImpFactory implements SessionImpFactory {

    @Override
    public SessionImp getImp(
            String remoteId,
            SecretKey secretKey,
            Pairing pairing,
            AuthToken authToken,
            Date lastAuthDate,
            Status status,
            Error error) {
        return new TestSessionImp(
                remoteId,
                secretKey,
                pairing,
                status,
                error,
                lastAuthDate,
                authToken);
    }

    @Override
    public SessionImp getImp(Session session) {
        return getImp(
                session.getRemoteId(),
                session.getSecretKey(),
                session.getPairing(),
                session.getAuthToken(),
                session.getLastAuthDate(),
                session.getStatus(),
                session.getError());
    }

}
