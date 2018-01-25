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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.mypico.jpico.crypto.messages.EncPicoReauthMessage;
import org.mypico.jpico.crypto.messages.EncServiceReauthMessage;
import org.mypico.jpico.crypto.messages.PicoReauthMessage;
import org.mypico.jpico.crypto.messages.ReauthState;
import org.mypico.jpico.crypto.messages.SequenceNumber;
import org.mypico.jpico.crypto.messages.ServiceReauthMessage;
import org.mypico.jpico.crypto.messages.EncryptedMessage.FieldDeserializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifier state machine for the continuous authentication protocol.
 * <p>
 * On each reauth, the sequence number is checked against the previous sequence number, and a new
 * sequence number is generated and both stored and sent.
 * <p>
 * <pre>
 *                                      ╭──────╮
 *                         pause        │      │pause
 *           ╭─────╮  ╭───────────▶ Paused ◀───╯
 *  continue │     │  │             │ │ │
 *           ╰──▶ Active ◀──────────╯ │ │
 *                 │  │    continue   │ │
 *            stop │  ╰───────╮       │ │ timeout
 *                 │  ╭───────┼───────╯ │
 *                 │  │ stop  ╰───────╮ │         ┆ ┆ ┆ ┆
 *                 │  │       timeout │ │         │ │ │ │
 *                 ▼  ▼               ▼ ▼         ▼ ▼ ▼ ▼
 *               Stopped            Timeout        Error
 * </pre>
 * <p>
 * NB: Error state can be entered from any state.
 * <p>
 * There is a layer of indirection, there is one message method that can trigger a pause, continue
 * or stop event.
 * <p>
 * <p>
 * This class follows a state machine design pattern. There are a well defined set of internal
 * states and for each state there is a <code>private</code> "state entry method". The state entry
 * methods are the only way to change the internal state of the prover. The public interface of the
 * prover consists of "event methods". These methods define the transition function of the prover
 * state machine, either calling a state entry method, doing nothing, or raising an
 * <code>{@link InvalidEventException}</code>, depending on the current state of the prover.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
final public class ContinuousVerifier implements IContinuousVerifier,
    Destroyable {

    public static final int activeTimeout = 10000, // 10 seconds
        pausedTimeout = 50000, // 50 seconds
        timeoutLeeway = 10000; // 10 seconds;

    private final SecretKey sessionEncryptionKey;
    private final IContinuousVerifier.Client clientInterface;
    private final PublicKey picoPublicKey;

    private SequenceNumber currentSequenceNumber;
    private int currentSessionId;
    private double timeoutTimestamp;
    private State state = State.ACTIVE;

    private final Logger LOGGER = LoggerFactory
        .getLogger(ContinuousVerifier.class);

    /**
     * Constructor.
     *
     * @param sessionEncryptionKey  The symmetric key for encrypting messages.
     * @param initialSequenceNumber The initial sequence number to use for the continuous
     *                              authentication.
     * @param clientInterface       The continuous verifier client interface.
     * @param picoPublicKey         The long term identity public key of the prover (Pico).
     */
    public ContinuousVerifier(final SecretKey sessionEncryptionKey,
                              final SequenceNumber initialSequenceNumber,
                              final IContinuousVerifier.Client clientInterface,
                              final PublicKey picoPublicKey) {

        // Verify the method's preconditions
        if (sessionEncryptionKey == null)
            throw new NullPointerException();
        if (initialSequenceNumber == null)
            throw new NullPointerException();
        if (clientInterface == null)
            throw new NullPointerException();
        if (picoPublicKey == null)
            throw new NullPointerException();

        this.sessionEncryptionKey = sessionEncryptionKey;
        this.currentSequenceNumber = initialSequenceNumber;
        this.clientInterface = clientInterface;
        this.picoPublicKey = picoPublicKey;
        setTimeout(activeTimeout + timeoutLeeway);
    }

    /* *************** State Entry Methods *************** */

    /**
     * Calling this method will move the continuous authentication into the active state, meaning
     * that re-authenticate will continue every time the timer() event is fired.
     */
    private void enterActive() {
        // Verify the method's preconditions
        assert (isDestroyed == false);

        state = State.ACTIVE;
        LOGGER.info("Enter Active");
        clientInterface.onResume(picoPublicKey);
    }

    /**
     * Calling this method will move the continuous authntication into the paused state, meaning
     * that no re-authenticate will take place until the prover enters the {@link State#ACTIVE}
     * state.
     */
    private void enterPaused() {
        // Verify the method's preconditions
        assert (isDestroyed == false);

        state = State.PAUSED;
        LOGGER.info("Enter Paused");
        clientInterface.onPause(picoPublicKey);
    }

    /**
     * Calling this method will move the continuous authentication into the stopped state, meaning
     * that no re-authenticate will take place.
     */
    private void enterStopped() {
        // Verify the method's preconditions
        assert (isDestroyed == false);

        state = State.STOPPED;
        LOGGER.info("Enter Stopped");
        clientInterface.onStop(picoPublicKey);
    }

    /**
     * Move the continuous authentication into a timeout state, meaning that a response was not
     * received within the timeout period.
     */
    private void enterTimeout() {
        // Verify the method's preconditions
        assert (isDestroyed == false);

        state = State.TIMEOUT;
        LOGGER.info("Enter Timeout");
        clientInterface.onStop(picoPublicKey);
    }

    /**
     * Move the continuous authentication into an error state.
     */
    private void enterError() {
        // Verify the method's preconditions
        assert (isDestroyed == false);

        state = State.ERROR;
        LOGGER.error("Enter Error");
        clientInterface.onStop(picoPublicKey);
    }

    /* *************** Event Methods *************** */

    /**
     * Enter an {@link State#ACTIVE} continuous authentication state.
     */
    private void cont() {
        switch (this.state) {
            case ACTIVE:
                break;
            case PAUSED:
                enterActive();
                break;
            default:
                throw new InvalidEventException();
        }
    }

    /**
     * Enter the {@link State#PAUSED} state.
     */
    private void pause() {
        switch (this.state) {
            case ACTIVE:
                enterPaused();
                break;
            case PAUSED:
                break;
            default:
                throw new InvalidEventException();
        }
    }

    /**
     * Stop the continuous authentication.
     */
    private void stop() {
        switch (this.state) {
            case ACTIVE:
            case PAUSED:
                enterStopped();
                break;
            default:
                throw new InvalidEventException();
        }
    }

    /**
     * The continuous authentication has timed-out, so enter a {@link State#TIMEOUT} state.
     */
    private void timeout() {
        switch (this.state) {
            case ACTIVE:
            case PAUSED:
                enterTimeout();
                break;
            default:
                throw new InvalidEventException();
        }
    }

    /**
     * Enter an error state.
     */
    private void error() {
        assert (isDestroyed == false);
        System.out.println("Called private error() method");
        enterError();
    }

    @Override
    public void reauth(final EncPicoReauthMessage msg)
        throws IOException {

        // Verify the method's preconditions
        if (msg == null)
            throw new NullPointerException();
        if (isDestroyed == true)
            throw new IllegalStateException();

        if (state == State.ACTIVE || state == State.PAUSED) {

            if (isTimedout()) {
                LOGGER.info("Timed out");
                timeout();
            }

            // Try to decrypt the PicoReauthMessage, state will be set to ERROR if this fails.
            PicoReauthMessage m = null;
            try {
                m = msg.decrypt(sessionEncryptionKey);
            } catch (InvalidKeyException e) {
                // Re-thrown unchecked because this signals incompatibility between the session
                // encryption key and the chosen encryption cipher. This is a configuration error
                // and is considered a fatal error from which the program probably can't (and
                // shouldn't try to) recover.
                throw new CryptoRuntimeException(e);
            } catch (InvalidAlgorithmParameterException e) {
                // Any of the other exceptions caught here indicate that the decryption failed due
                // to some error on the part of the prover.
                LOGGER.error("InvalidAlgorithmParameter Exception");
                error();
            } catch (IllegalBlockSizeException e) {
                LOGGER.error("IllegalBlockSize Exception");
                error();
            } catch (BadPaddingException e) {
                LOGGER.error("BadPadding Exception");
                error();
            } catch (FieldDeserializationException e) {
                LOGGER.error("FieldDeserialization Exception");
                error();
            }

            // Update current state. Note, reauth verification does not occur until the
            // else block below

            if (state == State.ERROR) {
                // Decryption failed, or session timed out.
            } else {
                // Verify reauthentication
                final SequenceNumber n = m.getSequenceNumber();
                if (this.currentSequenceNumber.verifyResponse(n)) {
                    // Reauthentication successful!
                    this.currentSessionId = msg.getSessionId();
                    // Increment the sequence number
                    this.currentSequenceNumber = n.getResponse();

                    switch (m.getReauthState()) {
                        case CONTINUE:
                            cont();
                            break;
                        case PAUSE:
                            pause();
                            break;
                        case STOP:
                            stop();
                            break;
                        default:
                            error();
                            break;
                    }
                } else {
                    // Reauthentication failed
                    System.out.println("Reauthentication failed, couldn't verify sequence number " + currentSequenceNumber.toString() + " against " + n.toString());
                    error();
                }
            }

        } else {
            throw new InvalidEventException();
        }
    }

    @Override
    public EncServiceReauthMessage getServiceReauth()
        throws IOException {
        ReauthState responseType = ReauthState.ERROR;
        int timeout = -1;
        switch (state) {
            case ACTIVE:
                responseType = ReauthState.CONTINUE;
                timeout = activeTimeout;
                break;
            case PAUSED:
                responseType = ReauthState.PAUSE;
                timeout = pausedTimeout;
                break;
            case STOPPED:
                responseType = ReauthState.STOP;
                timeout = -1;
                break;
            case TIMEOUT:
                responseType = ReauthState.ERROR;
                timeout = -1;
                break;
            case ERROR:
                responseType = ReauthState.ERROR;
                timeout = -1;
                break;
        }
        final ServiceReauthMessage serviceReauth = new ServiceReauthMessage(
            currentSessionId, responseType, timeout, currentSequenceNumber);
        EncServiceReauthMessage ercm;
        try {
            ercm = serviceReauth.encrypt(sessionEncryptionKey);
        } catch (InvalidKeyException e) {
            // Re-thrown unchecked because this signals incompatibility between the session
            // encryption key and the chosen encryption cipher. This is a configuration error
            // and is considered a fatal error from which the program probably can't (and
            // shouldn't try to) recover.
            throw new CryptoRuntimeException(e);
        }
        setTimeout(timeout + timeoutLeeway);
        return ercm;

    }

    /* *************** Helper Methods *************** */

    /**
     * Check whether the continous verifier is in a {@link State#TIMEOUT} state.
     *
     * @return true if the verifier has timed out, false o/w.
     */
    private boolean isTimedout() {

        assert (isDestroyed == false);

        return timeoutTimestamp < System.currentTimeMillis();
    }

    /**
     * Set the timeout period in milliseconds.
     *
     * @param timeout desired timeout in miliseconds
     */
    public void setTimeout(int timeout) {

        assert (isDestroyed == false);

        timeoutTimestamp = System.currentTimeMillis() + timeout;
    }

    /* *************** Destroyable *************** */
    private boolean isDestroyed = false;

    @Override
    public void destroy() throws DestroyFailedException {

        // Verify the method's preconditions
        if (isDestroyed == true)
            throw new IllegalStateException();

        isDestroyed = true;
        // TODO actually destroy sensitive data.
    }

    @Override
    public boolean isDestroyed() {
        return this.isDestroyed;
    }

    @Override
    public State getState() {

        // Verify the method's preconditions
        if (isDestroyed == true)
            throw new IllegalStateException();

        return state;
    }

}
