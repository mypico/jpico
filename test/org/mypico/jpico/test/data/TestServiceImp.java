package org.mypico.jpico.test.data;

import java.io.IOException;
import java.net.URI;

import org.mypico.jpico.data.service.ServiceImp;

public class TestServiceImp implements ServiceImp {

    private static int nextId = 0;

    private boolean isSaved = false;
    private int id = nextId++;
    private String name;
    private URI address;
    private byte[] commitment;

    TestServiceImp(
            String name,
            URI address,
            byte[] commitment) {
        this.name = name;
        this.address = address;
        this.commitment = commitment;
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
    public String getName() {
        return name;
    }

    @Override
    public void setAddress(URI address) {
        this.address = address;
    }

    @Override
    public URI getAddress() {
        return address;
    }

    @Override
    public byte[] getCommitment() {
        return commitment;
    }

}
