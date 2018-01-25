/*
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * This file is part of jpico.
 *
 * jpico is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * jpico is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with jpico. If not, see
 * <http://www.gnu.org/licenses/>.
 */


package org.mypico.jpico.comms;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.Callable;

import org.apache.commons.io.IOUtils;
import org.mypico.jpico.crypto.IContinuousVerifier;
import org.mypico.jpico.crypto.ProtocolViolationException;
import org.mypico.jpico.crypto.messages.EncPicoReauthMessage;
import org.mypico.jpico.crypto.messages.EncServiceReauthMessage;

/**
 * A sigma handler that uses a socket as its channel.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class SocketContinuousHandler implements Callable<Void> {

    public static final int MAX_MESSAGE_LENGTH = 1024;

    private final Socket socket;
    private final MessageSerializer serializer;
    private final IContinuousVerifier verifier;

    private DataInputStream dis = null;
    private DataOutputStream dos = null;

    /**
     * Constructor.
     *
     * @param socket     The socket to use for communication.
     * @param serializer A message serializer compatible with the remote verifier.
     * @param verifier   The sigma verifier to use.
     */
    public SocketContinuousHandler(
        final Socket socket,
        final MessageSerializer serializer,
        final IContinuousVerifier verifier) {
        this.socket = socket;
        this.serializer = serializer;
        this.verifier = verifier;
    }

    /**
     * Reads the length of the next message from the channel.
     *
     * @return The message length, as passed on the Rendezvous Point channel.
     * @throws IOException thrown if an error occurs reading from the channel.
     */
    private int readMessageLength() throws IOException {
        final int len = dis.readInt();
        if (len <= 0 || len > MAX_MESSAGE_LENGTH) {
            throw new IOException("Invalid message length");
        } else {
            return len;
        }
    }

    /**
     * Write the message length to the channel.
     *
     * @param len The length to write.
     * @throws IOException thrown if an error occurs reading from the channel.
     */
    private void writeMessageLength(final int len) throws IOException {
        if (len <= 0 || len > MAX_MESSAGE_LENGTH) {
            throw new IOException("Invalid message length");
        } else {
            dos.writeInt(len);
        }
    }

    @Override
    public Void call() throws EOFException, IOException, ProtocolViolationException {
        try {
            // Open I/O streams
            dis = new DataInputStream(socket.getInputStream());
            dos = new DataOutputStream(socket.getOutputStream());

            while (verifier.getState() == IContinuousVerifier.State.ACTIVE ||
                verifier.getState() == IContinuousVerifier.State.PAUSED) {
                // Read EncPicoReauthMessage from client:
                byte[] seprm = IOUtils.toByteArray(dis, readMessageLength());
                EncPicoReauthMessage eprm = serializer.deserialize(
                    seprm, EncPicoReauthMessage.class);

                // Pass to verifier and get next message
                verifier.reauth(eprm);
                EncServiceReauthMessage esrm = verifier.getServiceReauth();

                // Write EncServiceReauthMessage response back to client
                byte[] sesrm = serializer.serialize(esrm, EncServiceReauthMessage.class);
                writeMessageLength(sesrm.length);
                IOUtils.write(sesrm, dos);
                dos.flush();
            }
        } catch (IOException e) {
            // Re-throw for caller to deal with
            throw e;
        } finally {
            try {
                if (dis != null) {
                    dis.close();
                }
                if (dos != null) {
                    dos.close();
                }
            } catch (IOException e) {
                // Re-throw for caller to deal with
                throw e;
            }
        }
        return null;
    }
}
