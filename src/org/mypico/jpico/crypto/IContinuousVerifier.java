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


package org.mypico.jpico.crypto;

import java.io.IOException;
import java.security.PublicKey;

import org.mypico.jpico.crypto.messages.EncPicoReauthMessage;
import org.mypico.jpico.crypto.messages.EncServiceReauthMessage;

/**
 * Interface for the continuous authentication process on the verifier (service) side.
 * <p>
 * This runs the authentication process for the verifier (service).
 * <p>
 * Callback interface to be implemented by the Pico server when the client service application
 * needs to be notified of continuous authentication events.
 * <p>
 * <p>
 * This interface is used in the same way as {@link ISigmaVerifier.Client}, see its
 * documentation for an example.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public interface IContinuousVerifier {
    /**
     * Time to added to the timeout as an extra amount after the timeout set by
     * the service reauth
     * <p>
     * In the continuous prover, when a service reauth is received we schedule
     * a Pico reauth to be sent in the specified time. At the same time, we wait
     * for a server response which will come:
     * - In normal situations, just after the Pico reauth is sent. That is why
     * this timeoutLeeway is added.
     * - If the state changed, at any time. That is why we start reading from
     * the server as soon as we can.
     */
    public static final int timeoutLeeway = 10000; // 10 seconds;

    public static enum State {
        ACTIVE,
        PAUSED,
        STOPPED,
        TIMEOUT,
        ERROR;
    }

    /**
     * Callback interface to be implemented by the Pico server when the client service application
     * needs to be notified of continuous authentication events.
     * <p>
     * <p>
     * This interface is used in the same way as {@link ISigmaVerifier.Client}, see its
     * documentation for an example.
     *
     * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
     */
    public interface Client {
        public abstract void onPause(PublicKey picoPublicKey);

        public abstract void onStop(PublicKey picoPublicKey);

        public abstract void onResume(PublicKey picoPublicKey);
    }

    /**
     * @return the current state of the verifier.
     * @throws UnsupportedOperationException if specific verifier implementation does not support
     *                                       this method.
     */
    State getState() throws UnsupportedOperationException;

    /**
     * As part of a continuous authentication session, send a message to update the
     * verifier.
     *
     * @param msg the message including the current sequence number.
     * @throws IOException in case a network error occurs during sending of the reauth.
     */
    void reauth(EncPicoReauthMessage msg) throws IOException;

    /**
     * As part of a continuous authentication session, receives a message from the
     * verifier. This message will always be sent after a reauth, to update the
     * counter. But can be sent in other moments if the verifier wants to inform
     * some update in state.
     *
     * @return the service message, including the incremented sequence number.
     * null if no message is available
     * @throws IOException in case a network error occurs during receiving of the reauth.
     */
    EncServiceReauthMessage getServiceReauth() throws IOException;

    /**
     * Sets a timeout in the channel. This is used by the ContinuousProver in order to
     * set a sensible timeout depending on the timeout sent by the Continuous server
     * in the service reauth message.
     *
     * @param timeout desired timeout in miliseconds
     */
    void setTimeout(int timeout);
}
