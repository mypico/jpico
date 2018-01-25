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

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Interface for a TCP socket based Pico service, which maintains a stateful connection with the
 * Pico for the duration of each session.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class SocketCombinedProxy extends CombinedVerifierProxy {

    private final static Logger LOGGER =
        LoggerFactory.getLogger(SocketCombinedProxy.class.getSimpleName());
    private final static int MAXIMUM_MESSAGE_LEN_IN_BYTES = 65535;

    private final InetSocketAddress address;
    private final Socket socket;

    /**
     * Consructor.
     *
     * @param address    address of the remote verifier.
     * @param serializer a message serializer compatible with the remote verifier.
     */
    public SocketCombinedProxy(
        final InetSocketAddress address, final MessageSerializer serializer) {
        super(serializer);
        this.address = checkNotNull(address, "address cannot be null");
        this.socket = new Socket();
    }

    /**
     * Consructor.
     *
     * @param host       The TCP host address to connect to.
     * @param port       The TCP port to connect to.
     * @param serializer A message serializer compatible with the remote verifier.
     */
    public SocketCombinedProxy(
        final String host, final int port, final MessageSerializer serializer) {
        this(new InetSocketAddress(checkNotNull(host, "host cannot be null"), port), serializer);
    }

    /**
     * Consructor.
     *
     * @param socket     The socket to communicate over.
     * @param serializer A message serializer compatible with the remote verifier.
     */
    public SocketCombinedProxy(
        final Socket socket, final MessageSerializer serializer) {
        super(serializer);
        this.socket = socket;
        this.address = new InetSocketAddress(socket.getInetAddress(), socket.getPort());
    }

    @Override
    public void setTimeout(int timeout) {
        try {
            socket.setSoTimeout(timeout);
        } catch (SocketException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void lazyInit() throws IOException {
        // Lazily only connect the socket when it is first needed.
        if (!socket.isConnected()) {
            socket.connect(address);
        }
    }

    @Override
    protected byte[] getResponse(final byte[] serializedMessage) throws IOException {
        checkNotNull(serializedMessage, "serializedMessage cannot be null");

        writeMessage(serializedMessage);
        return readMessage();
    }

    /**
     * Write a serialized message to the socket.
     *
     * @param serializedMessage the serialized message to write.
     * @throws IOException
     */
    @Override
    protected void writeMessage(final byte[] serializedMessage) throws IOException {
        checkNotNull(serializedMessage, "serializedMessage cannot be null");
        final DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        // Check length of serialized message is within the valid range
        final int len = serializedMessage.length;
        if (len > 0 && len <= MAXIMUM_MESSAGE_LEN_IN_BYTES) {
            // Write message length
            dos.writeInt(len);

            // Write the message itself
            LOGGER.debug("Writing serialised message of {} bytes...", len);
            IOUtils.write(serializedMessage, dos);
            dos.flush();
            LOGGER.trace("Message written");
        } else {
            LOGGER.error("Invalid message length of {} bytes", len);
            throw new IOException(String.format("Invalid message length %d", len));
        }
    }

    /**
     * Read a serialized message from the socket.
     *
     * @return the serialized message read from the socket.
     * @throws IOException
     */
    @Override
    protected byte[] readMessage() throws IOException {
        final DataInputStream dis = new DataInputStream(socket.getInputStream());

        // Verify that the number of bytes in the message is within a sensible range
        final int len = dis.readInt();
        if (len > 0 && len <= MAXIMUM_MESSAGE_LEN_IN_BYTES) {
            // Read the bytes of the message
            LOGGER.debug("Reading serialised message of {} bytes...", len);
            final byte[] b = IOUtils.toByteArray(dis, len);
            LOGGER.trace("Message read");

            // Verify the method's postconditions
            assert (b != null);

            return b;
        } else {
            LOGGER.error("Invalid message length of {} bytes", len);
            throw new IOException(String.format("Invalid message length %d", len));
        }
    }

    /**
     * Get the socket being used for communication.
     *
     * @return The socket.
     */
    public Socket getSocket() {
        return socket;
    }
}
