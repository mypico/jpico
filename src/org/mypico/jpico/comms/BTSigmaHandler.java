package org.mypico.jpico.comms;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.mypico.jpico.crypto.ISigmaVerifier;

/**
 * Bluetooth input and output streams used for performing the SIGMA-I protocol over a Bluetooth
 * channel.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @see MessageSerializer
 */
public class BTSigmaHandler extends AbstractHandler {
    // Dummy class just so things will compile without having to include
    // the Bluecove libs (javax.microedition.io.StreamConnection)
    public class StreamConnection {
        public DataInputStream openInputStream() {
            // Do nothing
            return null;
        }

        public DataOutputStream openOutputStream() {
            // Do nothing
            return null;
        }

        public void close() {
            // Do nothing
        }
    }

    private final StreamConnection socket;
    private DataInputStream dis;
    private DataOutputStream dos;

    /**
     * Constructor.
     *
     * @param socket     The Bluetooth sockt to use for communication.
     * @param serializer A message serializer compatible with the remote verifier.
     * @param verifier   The Sigma Verifier to use for authentication.
     * @param continuous true if continuous authentication should be performed, false o/w.
     */
    public BTSigmaHandler(final StreamConnection socket, final MessageSerializer serializer, final ISigmaVerifier verifier, final boolean continuous) {
        super(serializer, verifier, continuous);
        this.socket = socket;
    }

    @Override
    protected DataInputStream getInputStream() throws IOException {
        if (dis == null) {
            dis = new DataInputStream(socket.openInputStream());
            ;
        }
        return dis;
    }

    @Override
    protected DataOutputStream getOutputStream() throws IOException {
        if (dos == null) {
            // Why is this BufferedOutputStream here?
            dos = new DataOutputStream(new BufferedOutputStream(socket.openOutputStream()));
        }
        return dos;
    }

    @Override
    protected void finish() throws IOException {
        super.finish();
        if (socket != null) {
            socket.close();
        }
    }
}

