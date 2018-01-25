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

import org.apache.commons.io.IOUtils;
import org.mypico.rendezvous.RendezvousChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A proxy of a remote combined verifier that uses a Rendezvous Point channel to communicate.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see MessageSerializer
 */
public class RendezvousSigmaProxy extends CombinedVerifierProxy {

    private final static Logger LOGGER =
        LoggerFactory.getLogger(RendezvousSigmaProxy.class.getSimpleName());

    private final RendezvousChannel channel;

    /**
     * Constructor.
     *
     * @param channel    The Rendezvous Point channel to use for communication.
     * @param serializer A message serializer compatible with the remote verifier.
     */
    public RendezvousSigmaProxy(RendezvousChannel channel, MessageSerializer serializer) {
        super(serializer);
        this.channel = channel;
    }

    @Override
    public void setTimeout(int timeout) {
        channel.setTimeout(timeout);
    }

    @Override
    protected byte[] getResponse(byte[] serializedMessage) throws IOException {
        writeMessage(serializedMessage);
        return readMessage();
    }

    @Override
    protected void writeMessage(byte[] serializedMessage) throws IOException {
        final DataOutputStream dos = new DataOutputStream(
            new BufferedOutputStream(channel.getOutputStream()));

        final int numBytesInMessage = serializedMessage.length;
        LOGGER.debug("Writing serialised message of {} bytes...", numBytesInMessage);
        dos.writeInt(numBytesInMessage);
        IOUtils.write(serializedMessage, dos);
        dos.flush();
        LOGGER.debug("Message written");
    }

    @Override
    protected byte[] readMessage() throws IOException {
        // Read the response from the socket
        final DataInputStream dis = new DataInputStream(channel.getInputStream());

        final int numBytesInMessage = dis.readInt();
        LOGGER.debug("Reading serialised message of {} bytes...", numBytesInMessage);
        final byte[] b = IOUtils.toByteArray(dis, numBytesInMessage);
        LOGGER.debug("Message read");
        return b;
    }
}
