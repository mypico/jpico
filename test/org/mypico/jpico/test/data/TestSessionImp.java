package org.mypico.jpico.test.data;

import java.io.IOException;
import java.util.Date;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.pairing.Pairing;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImp;
import org.mypico.jpico.data.session.Session.Error;
import org.mypico.jpico.data.session.Session.Status;

public class TestSessionImp implements SessionImp {

    private static int nextId = 0;

    private boolean isSaved = false;
    private int id;
    private String remoteId;
    private SecretKey secretKey;
    private Pairing pairing;
    private Session.Status status;
    private Session.Error error;
    private Date lastAuthDate;
    private AuthToken authToken;

    TestSessionImp(
            String remoteId,
            SecretKey secretKey,
            Pairing pairing,
            Session.Status status,
            Session.Error error,
            Date lastAuthDate,
            AuthToken authToken) {
        this.id = nextId++;
        this.remoteId = remoteId;
        this.secretKey = secretKey;
        this.pairing = pairing;
        this.status = status;
        this.error = error;
        this.lastAuthDate = lastAuthDate;
        this.authToken = authToken;
    }

    @Override
    public void save() throws IOException {
        isSaved = true;
    }

    @Override
    public boolean isSaved() {
        return isSaved;
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public String getRemoteId() {
        return remoteId;
    }

    @Override
    public SecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public Pairing getPairing() {
        return pairing;
    }

    @Override
    public Status getStatus() {
        return status;
    }

    @Override
    public void setStatus(Status status) {
        this.status = status;
    }

    @Override
    public Error getError() {
        return error;
    }

    @Override
    public void setError(Error error) {
        this.error = error;
    }

    @Override
    public Date getLastAuthDate() {
        return lastAuthDate;
    }

    @Override
    public void setLastAuthDate(Date date) {
        this.lastAuthDate = date;
    }

    @Override
    public boolean hasAuthToken() {
        return (authToken != null);
    }

    @Override
    public AuthToken getAuthToken() throws IllegalStateException {
        return authToken;
    }

    @Override
    public void clearAuthToken() {
        authToken = null;
    }

}
