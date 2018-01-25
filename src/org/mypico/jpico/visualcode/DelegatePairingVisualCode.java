package org.mypico.jpico.visualcode;

import java.net.URI;
import java.security.PublicKey;

import org.mypico.jpico.Preconditions;
import org.mypico.jpico.crypto.HashUtils;
import org.mypico.jpico.crypto.Nonce;

import com.google.gson.annotations.SerializedName;

/**
 * Lens visual code for delegating authority.
 *
 * @author David Llewellyn-Jones &gt;David.Llewellyn-Jones@cl.cam.ac.uk&lt;
 * @author Seb Aebischer &lt;seb.aebischer@cl.cam.ac.uk&gt;
 */
public class DelegatePairingVisualCode extends VisualCode implements WithTerminalDetails {

    public static String TYPE = "DP";

    @SerializedName("tn")
    private String terminalName;
    @SerializedName("n")
    private Nonce nonce;
    @SerializedName("td")
    private TerminalDetails terminal;

    /**
     * Constructor.
     */
    protected DelegatePairingVisualCode() {
        super(TYPE);
    }

    /**
     * Factory for creating {@link DelegatePairingVisualCode} instances from the data provided.
     *
     * @param terminalName      The terminal name.
     * @param nonce             The nonce to use for the session.
     * @param terminalAddress   The address of th terminal.
     * @param terminalPublicKey The long term identity public key of the terminal.
     * @return a {@link DelegatePairingVisualCode} instance.
     */
    public static DelegatePairingVisualCode getInstance(
        String terminalName,
        Nonce nonce,
        URI terminalAddress,
        PublicKey terminalPublicKey) {
        final DelegatePairingVisualCode code = new DelegatePairingVisualCode();
        code.terminalName = Preconditions.checkNotNullOrEmpty(
            terminalName, "terminalName cannot be null or empty");
        code.nonce = com.google.common.base.Preconditions.checkNotNull(
            nonce, "nonce cannot be empty");
        code.terminal = TerminalDetails.getInstance(
            terminalAddress, HashUtils.sha256Key(terminalPublicKey));
        return code;
    }

    /**
     * Get the terminal name.
     *
     * @return the terminal name.
     */
    public String getTerminalName() {
        return terminalName;
    }

    /**
     * Get the session nonce.
     *
     * @return the session nonce.
     */
    public Nonce getNonce() {
        return nonce;
    }

    @Override
    public byte[] getTerminalCommitment() {
        return terminal.getTerminalCommitment();
    }

    @Override
    public URI getTerminalAddress() {
        return terminal.getTerminalAddress();
    }

    @Override
    public boolean hasTerminal() {
        return (terminal != null && terminal.hasTerminal());
    }

    @Override
    public boolean isValid() {
        return super.isValid() &&
            terminalName != null &&
            nonce != null &&
            terminal != null;
    }

}
