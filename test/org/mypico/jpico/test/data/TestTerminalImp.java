package org.mypico.jpico.test.data;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.mypico.jpico.data.terminal.Terminal.Imp;

public class TestTerminalImp implements Imp {
	
	private static int nextId = 0;
	
	private boolean isSaved = false;
	private int id = nextId++;
	private String name;
	private byte[] commitment;
	private PublicKey picoPublicKey;
	private PrivateKey picoPrivateKey;
	
	public TestTerminalImp(
			String name, byte[] commitment, PublicKey picoPublicKey, PrivateKey picoPrivateKey) {
		this.name = name;
		this.commitment = commitment;
		this.picoPublicKey = picoPublicKey;
		this.picoPrivateKey = picoPrivateKey;
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
	public void delete() throws IOException {
		if (isSaved) {
			isSaved = false;
		} else {
			throw new IllegalStateException("cannot save an unsaved terminal");
		}
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
	public byte[] getCommitment() {
		return commitment;
	}

	@Override
	public PublicKey getPicoPublicKey() {
		return picoPublicKey;
	}

	@Override
	public PrivateKey getPicoPrivateKey() {
		return picoPrivateKey;
	}
}
