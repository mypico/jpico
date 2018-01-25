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

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.concurrent.Callable;

import org.apache.commons.io.IOUtils;
import org.mypico.jpico.crypto.ISigmaVerifier;
import org.mypico.jpico.crypto.ProtocolViolationException;
import org.mypico.jpico.crypto.messages.EncPicoAuthMessage;
import org.mypico.jpico.crypto.messages.EncServiceAuthMessage;
import org.mypico.jpico.crypto.messages.EncStatusMessage;
import org.mypico.jpico.crypto.messages.StartMessage;
import org.mypico.rendezvous.RendezvousChannel;

/**
 * A sigma handler that uses the Rendezvous Point as its channel.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see AbstractHandler
 * @see MessageSerializer
 */
public class RendezvousSigmaHandler extends AbstractHandler implements Callable<Void> {

    public static final int MAX_MESSAGE_LENGTH = 1000000; ///10240;

    private final MessageSerializer serializer;
    private final ISigmaVerifier verifier;
    private DataInputStream dis;
    private DataOutputStream dos;
    private boolean shouldContinue;
    private final RendezvousChannel channel;

    /**
     * Constructor.
     *
     * @param channel    The Rendezvous Point channel to use for communication.
     * @param serializer A message serializer compatible with the remote verifier.
     * @param verifier   The sigma verifier to use.
     */
    public RendezvousSigmaHandler(
        final RendezvousChannel channel,
        final MessageSerializer serializer,
        final ISigmaVerifier verifier) {
        //don't want to upset all existing Rendezvous code, so just assume not continuous authentication for now
        super(serializer, verifier, false);
        this.serializer = serializer;
        this.verifier = verifier;
        shouldContinue = true;

        this.channel = channel;

        // Open I/O streams
        dis = new DataInputStream(channel.getInputStream());
        dos = new DataOutputStream(new BufferedOutputStream(channel.getOutputStream()));
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
            throw new IOException("Invalid message length " + len + " (max=" + MAX_MESSAGE_LENGTH + ")");
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
            throw new IOException("Invalid message length " + len + " (max=" + MAX_MESSAGE_LENGTH + ")");
        } else {
            dos.writeInt(len);
        }
    }

    @Override
    public Void call() throws IOException, ProtocolViolationException {
        try {
            if (shouldContinue) {
                // FIRST ROUND-TRIP:
                // Read StartMessage from client
                final byte[] ssm = IOUtils.toByteArray(dis, readMessageLength());
                if (!shouldContinue) {
                    // Abort, abort!!
                    return null;
                    // Surely there's a nice way?
                }

                final StartMessage sm = serializer.deserialize(ssm, StartMessage.class);

                // Pass to verifier and get next message
                final EncServiceAuthMessage esam = verifier.start(sm);

                // Write EncServiceAuthMessage response back to client
                final byte[] sesam = serializer.serialize(
                    esam, EncServiceAuthMessage.class);

                writeMessageLength(sesam.length);
                IOUtils.write(sesam, dos);
                dos.flush();
                if (!shouldContinue) {
                    // Abort, abort!!
                    return null;
                }

                // SECOND ROUND-TRIP:
                // Read EncAuthMessage from client:
                final byte[] seam = IOUtils.toByteArray(dis, readMessageLength());

                final EncPicoAuthMessage eam = serializer.deserialize(
                    seam, EncPicoAuthMessage.class);

                // Pass to verifier and get next message
                final EncStatusMessage esm = verifier.authenticate(eam);

                // Write EncStatusMessage response back to client
                final byte[] sesm = serializer.serialize(esm, EncStatusMessage.class);
                writeMessageLength(sesm.length);
                IOUtils.write(sesm, dos);
                dos.flush();
            }
        } catch (IOException e) {
            // Re-throw for caller to deal with
            throw e;
        } catch (ProtocolViolationException e) {
            // Re-throw for caller to deal with
            throw e;
        } finally {
            try {
                dis.close();
                dos.close();
            } catch (IOException e) {
                // Re-throw for caller to deal with
                throw e;
            }
        }
        return null;
    }

    /**
     * Call to abort the protocol.
     */
    public void abort() {
        shouldContinue = false;
    }

    /**
     * Get the input stream for the channel.
     *
     * @return The input stream.
     * @throws IOException thrown if an error occurs getting the channel input stream.
     */
    protected DataInputStream getInputStream() throws IOException {
        if (dis == null) {
            dis = new DataInputStream(channel.getInputStream());
            ;
        }
        return dis;
    }

    @Override
    protected DataOutputStream getOutputStream() throws IOException {
        if (dos == null) {
            // Why is this BufferedOutputStream here?
            dos = new DataOutputStream(new BufferedOutputStream(channel.getOutputStream()));
        }
        return dos;
    }
}