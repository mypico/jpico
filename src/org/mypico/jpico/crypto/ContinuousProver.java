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

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.mypico.jpico.crypto.messages.EncPicoReauthMessage;
import org.mypico.jpico.crypto.messages.EncServiceReauthMessage;
import org.mypico.jpico.crypto.messages.PicoReauthMessage;
import org.mypico.jpico.crypto.messages.ReauthState;
import org.mypico.jpico.crypto.messages.SequenceNumber;
import org.mypico.jpico.crypto.messages.ServiceReauthMessage;
import org.mypico.jpico.crypto.messages.EncryptedMessage.FieldDeserializationException;
import org.mypico.jpico.data.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * When created with a session, the ContinuousAuthenticator reauthenticates
 * whenever the timer event is fired.
 * <p>
 * State machine
 * <p>
 * <pre>
 *                                      ╭─────╮
 *                         pause        │     │pause
 *           ╭─────╮  ╭───────────▶ Paused ◀──╯
 *  continue │     │  │              │  │
 *           ╰──▶ Active ◀───────────╯  │
 *                 │       continue     │
 *            stop │                    │
 *                 │  ╭─────────────────╯
 *                 │  │ stop              ┆ ┆ ┆
 *                 │  │                   │ │ │
 *                 ▼  ▼                   ▼ ▼ ▼
 *               Stopped                  Error
 * </pre>
 * <p>
 * NB: Error state can be entered from any state.
 * <p>
 * <p>
 * <p>
 * The continue and pause events move the state machine.
 * <p>
 * It simply allows the implementor to use the most natural timer construct
 * available to them.
 * <p>
 * Need to define what happens if pause, resume or stop events happen
 * unexpectedly.
 * <p>
 * The error event can only be triggered internally.
 *
 * @author Alexander Dalgleish <amd96@cam.ac.uk>
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
final public class ContinuousProver implements Destroyable {

    private final Logger LOGGER = LoggerFactory
        .getLogger(ContinuousProver.class);

    public static enum State {
        ACTIVE, PAUSED, STOPPED, ERROR
    }

    public interface ProverStateChangeNotificationInterface {

        public void sessionPaused(final Session session);

        public void sessionContinued(final Session session);

        public void sessionStopped(final Session session);

        public void sessionError(final Session session);

        public void tick(final Session session);
    }

    public interface SchedulerInterface {

        /**
         * The scheduler should call updateVerifier on the given prover within
         * the time specified, disregarding the previously scheduled event.
         *
         * @param milliseconds Set the time before a reply is expected, in milliseconds.
         * @param prover       The prover to apply the timer to.
         */
        public void setTimer(int milliseconds, ContinuousProver prover);

        /**
         * The scheduler should clear any scheduled calls to updateVerifier for
         * the specified prover.
         *
         * @param prover The prover to clear the timer for.
         */
        public void clearTimer(ContinuousProver prover);
    }

    private State state = State.ACTIVE;
    private int requestedTimeout;
    private final Session session;
    private final IContinuousVerifier serviceInterface;
    private final ProverStateChangeNotificationInterface proverStateChangeNotificationInterface;

    private final SchedulerInterface schedulerInterface;

    private SequenceNumber picoSequenceNumber;
    private SequenceNumber serviceSequenceNumber;

    private class PollService implements Runnable {
        private final Logger LOGGER = LoggerFactory
            .getLogger(PollService.class);

        private ContinuousProver prover;

        PollService(ContinuousProver prover) {
            this.prover = prover;
        }

        public void run() {
            LOGGER.info("Starting continuout authentication thread.");
            for (; ; ) {
                prover.getServiceMessage();
                serviceInterface.setTimeout(requestedTimeout + IContinuousVerifier.timeoutLeeway);

                synchronized (prover) {
                    if (state != State.ERROR) {
                        // Be ready to reply
                        schedulerInterface.setTimer(requestedTimeout, prover);
                    } else {
                        schedulerInterface.clearTimer(prover);
                        return;
                    }

                    proverStateChangeNotificationInterface.tick(prover.session);
                }
            }
        }
    }

    /**
     * Constructor.
     *
     * @param session                                The current session, including the secret key
     * @param serviceInterface                       The connection from the SigmaProver, may be a socket or an
     *                                               HTTP route.
     * @param proverStateChangeNotificationInterface The application can be updated by callbacks by implementing
     *                                               this interface.
     * @param schedulerInterface                     The implementor of the SchedulerInterface must call
     *                                               prover.updateverifier() exactly once within the time specified
     *                                               (i.e. it can be called earlier).
     * @param currentSequenceNumber                  The sequence number on the prover side must increment with
     *                                               each message sent to ensure freshness.
     * @param pollServiceExecutor                    The {@link Executor} thread to use to maintain the continuous
     *                                               session.
     */
    public ContinuousProver(Session session, IContinuousVerifier serviceInterface,
                            ProverStateChangeNotificationInterface proverStateChangeNotificationInterface,
                            SchedulerInterface schedulerInterface, SequenceNumber currentSequenceNumber,
                            Executor pollServiceExecutor) {
        this.serviceInterface = checkNotNull(serviceInterface);
        this.session = checkNotNull(session);
        this.proverStateChangeNotificationInterface = checkNotNull(proverStateChangeNotificationInterface);
        this.schedulerInterface = checkNotNull(schedulerInterface);
        this.picoSequenceNumber = checkNotNull(currentSequenceNumber);
        this.serviceSequenceNumber = null;
        pollServiceExecutor.execute(new PollService(this));
    }

	/* ************************ State Entry Methods ************************ */

    /**
     * Calling this method will move the continuous authntication into the active state, meaning
     * that re-authenticate will continue every time the timer() event is fired.
     */
    private void enterActive() {
        assert (isDestroyed == false);
        state = State.ACTIVE;
        updateVerifier();
        proverStateChangeNotificationInterface.sessionContinued(session);
    }

    /**
     * Calling this method will move the continuous authentication into the paused state, meaning
     * that no re-authenticate will take place until the prover enters the {@link State#ACTIVE}
     * state.
     */
    private void enterPaused() {
        assert (isDestroyed == false);
        state = State.PAUSED;
        updateVerifier();
        proverStateChangeNotificationInterface.sessionPaused(session);
    }

    /**
     * Calling this method will move the continuous authentication into the stopped state, meaning
     * that no re-authenticate will take place.
     */
    private void enterStopped() {
        assert (isDestroyed == false);
        state = State.STOPPED;
        updateVerifier();
        proverStateChangeNotificationInterface.sessionStopped(session);
    }

    /**
     * Move the continuous authentication into an error state.
     *
     * @param e The exception that caused the error state.
     */
    private void enterError(Exception e) {
        assert (isDestroyed == false);
        state = State.ERROR;
        proverStateChangeNotificationInterface.sessionError(session);
    }

	/* ****************************** Signals ****************************** */

    /**
     * Update the state.
     */
    public synchronized void updateVerifier() {

        if (isDestroyed == true)
            throw new IllegalStateException();

        if (state == State.ACTIVE || state == State.PAUSED || state == State.STOPPED) {
            try {
                // Generate response to the current sequenceNumber.
                ReauthState t;
                switch (this.state) {
                    case ACTIVE:
                        t = ReauthState.CONTINUE;
                        break;
                    case PAUSED:
                        t = ReauthState.PAUSE;
                        break;
                    case STOPPED:
                        t = ReauthState.STOP;
                        break;
                    default: // Never happens if no concurrent manipulation;
                        throw new IllegalStateException();
                }
                final PicoReauthMessage picoReauthMessage = new PicoReauthMessage(
                    Integer.parseInt(session.getRemoteId()), t, picoSequenceNumber);

                // Encrypt the reauth message
                EncPicoReauthMessage encPicoReauthMessage;
                try {
                    encPicoReauthMessage = picoReauthMessage.encrypt(session.getSecretKey());
                } catch (InvalidKeyException e) {
                    // Re-thrown unchecked because this signals incompatibility
                    // between the session
                    // encryption key and the chosen encryption cipher. This is
                    // a configuration error
                    // and is considered a fatal error from which the program
                    // probably can't (and
                    // shouldn't try to) recover.
                    throw new CryptoRuntimeException(e);
                }

                LOGGER.info("Writing Pico reauth message " + picoSequenceNumber.toString());
                // Send it and get the encrypted response
                serviceInterface.reauth(encPicoReauthMessage);
                // Update sequence number for next message
                picoSequenceNumber = picoSequenceNumber.getResponse();

            } catch (IOException e) {
                e.printStackTrace();
                this.error(e);
                return;
            }
        } // else do nothing
    }

    /**
     * Get the message sent by the service at the last authentication step.
     */
    public void getServiceMessage() {
        if (isDestroyed == true)
            throw new IllegalStateException();

        if (state == State.ACTIVE || state == State.PAUSED || state == State.STOPPED) {
            try {
                LOGGER.info("Reading service reauth message");
                // get the encrypted response
                final EncServiceReauthMessage encServiceReauthMessage = serviceInterface.getServiceReauth();

                // Decrypt the response
                ServiceReauthMessage serviceReauthMessage;
                try {
                    serviceReauthMessage = encServiceReauthMessage.decrypt(session.getSecretKey());
                } catch (InvalidKeyException e) {
                    // Re-thrown unchecked because this signals incompatibility
                    // between the session
                    // encryption key and the chosen encryption cipher. This is
                    // a configuration
                    // error and is considered a fatal error from which the
                    // program probably can't
                    // (and shouldn't try to) recover.
                    throw new CryptoRuntimeException(e);
                } catch (InvalidAlgorithmParameterException e) {
                    // Any of the other exceptions caught here indicate that the
                    // decryption failed due
                    // to some error on the part of the prover.
                    error();
                    return;
                } catch (IllegalBlockSizeException e) {
                    error();
                    return;
                } catch (BadPaddingException e) {
                    error();
                    return;
                } catch (FieldDeserializationException e) {
                    error();
                    return;
                }

                // Verify the service's response
                final SequenceNumber c3 = serviceReauthMessage.getSequenceNumber();
                if (serviceSequenceNumber == null) {
                    serviceSequenceNumber = c3;
                } else if (!serviceSequenceNumber.getResponse().equals(c3)) {
                    LOGGER.error("Wrong sequence number");
                    this.error();
                    return;
                }

                final ReauthState newReauthState = serviceReauthMessage.getReauthState();

                switch (newReauthState) {
                    case CONTINUE:
                        resume();
                        break;
                    case PAUSE:
                        pause();
                        break;
                    case STOP:
                        stop();
                        break;
                    case ERROR:
                        // Fall through
                    default:
                        error();
                        break;

                }

                if (state != State.ERROR) {
                    LOGGER.info("Success, updating sequence number " + c3.toString());
                    this.serviceSequenceNumber = c3;
                    this.requestedTimeout = serviceReauthMessage.getTimeout();
                }
            } catch (IOException e) {
                e.printStackTrace();
                this.error(e);
                return;
            }
        } // else do nothing

    }

    /**
     * Enter the {@link State#PAUSED} state.
     */
    synchronized public void pause() {
        if (isDestroyed == true)
            throw new IllegalStateException();

        switch (state) {
            case ACTIVE:
                enterPaused();
                break;
            case PAUSED:
                // Already on paused state. Do nothing
                break;
            case STOPPED:
                LOGGER.error("Trying to pause from session in stopped state");
                break;
            case ERROR:
                LOGGER.error("Trying to pause from session in error state");
                break;
        }
    }

    /**
     * Enter an {@link State#ACTIVE} continuous authentication state.
     */
    synchronized public void resume() {
        if (isDestroyed == true)
            throw new IllegalStateException();
        switch (this.state) {
            case ACTIVE:
                // Already on active state. Do nothing
                break;
            case PAUSED:
                enterActive();
                break;
            case STOPPED:
                LOGGER.error("Trying to resume from session in stopped state");
                break;
            case ERROR:
                LOGGER.error("Trying to resume from session in error state");
                break;
        }
    }

    /**
     * Stop the continuous authentication.
     */
    synchronized public void stop() {
        if (isDestroyed == true)
            throw new IllegalStateException();

        switch (this.state) {
            case ACTIVE:
            case PAUSED:
                enterStopped();
                break;
            case STOPPED:
                // Already stopped. Do nothing
                break;
            case ERROR:
                LOGGER.error("Trying to stop from session in error state");
                break;
        }
    }

    /**
     * Enter an error state.
     */
    private void error() {
        assert (isDestroyed == false);
        enterError(null);
    }

    /**
     * Enter an error state.
     *
     * @param e The exception that caused the error state.
     */
    private void error(Exception e) {
        assert (isDestroyed == false);
        enterError(e);
    }

	/* **************************** Destroyable **************************** */

    /* NB: this can be read by many threads, hence volatile. */
    private volatile boolean isDestroyed = false;

    @Override
    synchronized public void destroy() throws DestroyFailedException {
        // TODO: Finish
        isDestroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }

}
