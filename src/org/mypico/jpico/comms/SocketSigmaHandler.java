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
import java.net.Socket;

import org.mypico.jpico.crypto.ISigmaVerifier;

/**
 * An implementation of the {@link AbstractHandler} abstract class. This provides an input/output
 * stream using a TCP socket as the channel of communication.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see AbstractHandler
 */
public class SocketSigmaHandler extends AbstractHandler {

    private final Socket socket;
    private DataInputStream dis;
    private DataOutputStream dos;

    /**
     * Constructor.
     *
     * @param socket     The socket to use for communication.
     * @param serializer A message serializer compatible with the remote verifier.
     * @param verifier   An implementation fo a sigma verifier.
     * @param continuous true if continuous authentication should be used, false o/w.
     */
    public SocketSigmaHandler(final Socket socket, final MessageSerializer serializer, final ISigmaVerifier verifier, final boolean continuous) {
        super(serializer, verifier, continuous);
        this.socket = socket;
    }

    @Override
    protected DataInputStream getInputStream() throws IOException {
        if (dis == null) {
            dis = new DataInputStream(socket.getInputStream());
            ;
        }
        return dis;
    }

    @Override
    protected DataOutputStream getOutputStream() throws IOException {
        if (dos == null) {
            // Why is this BufferedOutputStream here?
            dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
        }
        return dos;
    }
}