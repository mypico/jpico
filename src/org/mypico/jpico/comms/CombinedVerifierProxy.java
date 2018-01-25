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

import java.io.IOException;

import org.mypico.jpico.crypto.ICombinedVerifier;
import org.mypico.jpico.crypto.messages.EncPicoReauthMessage;
import org.mypico.jpico.crypto.messages.EncServiceReauthMessage;

/**
 * Abstract base class for proxies of remote combined verifiers.
 * <p>
 * <p>Subclasses must provide an implementation of {@link #getResponse(byte[]) sendRequest} method
 * which transmits a serialized message to the remote verifier and returns its serialized response.
 * Subclasses should pass an appropriate {@link MessageSerializer} to the super constructor.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see MessageSerializer
 */
public abstract class CombinedVerifierProxy extends SigmaVerifierProxy implements ICombinedVerifier {

    /**
     * Constructor.
     *
     * @param serializer A message serializer compatible with the remote verifier.
     */
    protected CombinedVerifierProxy(final MessageSerializer serializer) {
        super(serializer);
    }

    @Override
    public final void reauth(EncPicoReauthMessage msg) throws IOException {
        final byte[] serializedMsg = serializer.serialize(msg, EncPicoReauthMessage.class);
        ensureInitialised();
        writeMessage(serializedMsg);
    }

    /**
     * Read the next ServiceReauthMessage.
     *
     * @return The message read.
     * @throws IOException thrown if an error occurs reading the message.
     */
    public final EncServiceReauthMessage getServiceReauth() throws IOException {
        final byte[] serializedResponse = readMessage();
        return serializer.deserialize(serializedResponse, EncServiceReauthMessage.class);
    }

    @Override
    public State getState() {
        throw new UnsupportedOperationException("getState not supported by verifier proxies");
    }
}
