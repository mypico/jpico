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

import org.mypico.jpico.crypto.ISigmaVerifier;
import org.mypico.jpico.crypto.messages.EncPicoAuthMessage;
import org.mypico.jpico.crypto.messages.EncServiceAuthMessage;
import org.mypico.jpico.crypto.messages.EncStatusMessage;
import org.mypico.jpico.crypto.messages.StartMessage;

/**
 * Abstract base class for proxies of sigma verifiers.
 * <p>
 * <p>Subclasses must provide an implementation of {@link #getResponse(byte[])} method
 * which transmits a serialized message to the remote verifier and returns its serialized response.
 * Subclasses should pass an appropriate {@link MessageSerializer} to the super constructor. The
 * {@link #readMessage()} and {@link #writeMessage(byte[])} must also be implemented for reading
 * and writing messages to the channel respectively.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see MessageSerializer
 */
public abstract class SigmaVerifierProxy implements ISigmaVerifier {

    protected final MessageSerializer serializer;
    private boolean initialised = false;

    /**
     * Constructor.
     *
     * @param serializer A message serializer compatible with the remote verifier.
     */
    public SigmaVerifierProxy(final MessageSerializer serializer) {
        this.serializer = serializer;
    }

    /**
     * Subclasses may override this method if they want to lazily initialise resources immediately
     * before the first message through this proxy.
     *
     * @throws IOException if an <code>IOException</code> occurs during the initialisation.
     */
    protected void lazyInit() throws IOException {
    }

    /**
     * Ensure lazy initialisation has taken place.
     * <p>
     * <p>This method will not call {@link #lazyInit()} again, if it has already been called.
     *
     * @throws IOException if an <code>IOException</code> occurs during the initialisation.
     */
    protected final void ensureInitialised() throws IOException {
        if (!initialised) {
            lazyInit();
        }
        initialised = true;
    }

    /**
     * Send a serialized message to the remote verifier and return its serialized response.
     *
     * @param serializedMessage the serialized message to send.
     * @return the remote verifier's serialized response.
     * @throws IOException if there is a problem communicating with the remote verifier.
     */
    protected abstract byte[] getResponse(byte[] serializedMessage) throws IOException;

    /**
     * Reads a message from the channel
     *
     * @return the remote verifier's message
     * @throws IOException
     */
    protected abstract byte[] readMessage() throws IOException;

    /**
     * Sends a message to the remote verifier
     *
     * @param serializedMessage message to be sent
     * @throws IOException
     */
    protected abstract void writeMessage(byte[] serializedMessage) throws IOException;

    @Override
    public final EncServiceAuthMessage start(final StartMessage msg) throws IOException {
        final byte[] serializedMsg = serializer.serialize(msg, StartMessage.class);
        ensureInitialised();
        final byte[] serializedResponse = getResponse(serializedMsg);
        return serializer.deserialize(serializedResponse, EncServiceAuthMessage.class);
    }

    @Override
    public final EncStatusMessage authenticate(EncPicoAuthMessage msg) throws IOException {
        final byte[] serializedMsg = serializer.serialize(msg, EncPicoAuthMessage.class);
        ensureInitialised();
        final byte[] serializedResponse = getResponse(serializedMsg);
        return serializer.deserialize(serializedResponse, EncStatusMessage.class);
    }
}
