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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.concurrent.Executor;

import org.mypico.jpico.crypto.ContinuousProver.ProverStateChangeNotificationInterface;
import org.mypico.jpico.crypto.ContinuousProver.SchedulerInterface;
import org.mypico.jpico.crypto.NewSigmaProver.ProverAuthRejectedException;
import org.mypico.jpico.crypto.NewSigmaProver.VerifierAuthFailedException;
import org.mypico.jpico.crypto.messages.ReauthState;
import org.mypico.jpico.crypto.messages.SequenceNumber;
import org.mypico.jpico.crypto.messages.ReauthState.InvalidReauthStateIndexException;
import org.mypico.jpico.crypto.util.LengthPrependedDataInputStream;
import org.mypico.jpico.data.pairing.KeyPairing;
import org.mypico.jpico.data.session.Session;
import org.mypico.jpico.data.session.SessionImp;
import org.mypico.jpico.data.session.SessionImpFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;

/**
 * Run the SIGMA-I protocol for the prover (Pico).
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
@Deprecated
final public class ServiceSigmaProver {

    private static final byte VERSION_1_0 = (byte) 1;

    private final static Logger LOGGER =
        LoggerFactory.getLogger(ServiceSigmaProver.class.getSimpleName());

    private final KeyPairing pairing;
    private final SessionImpFactory sessionFactory;
    private final NewSigmaProver prover;
    private Optional<SequenceNumber> sequenceNumber = Optional.absent();

    /**
     * Constructor.
     *
     * @param pairing        The pairing to use for authentication.
     * @param verifier       A concrete sigma verifier implementation.
     * @param sessionFactory a factory which produces concrete {@link SessionImp} instances.
     */
    public ServiceSigmaProver(
        final KeyPairing pairing,
        final ISigmaVerifier verifier,
        final SessionImpFactory sessionFactory) {
        this.pairing = checkNotNull(pairing, "pairing cannot be null");
        checkNotNull(verifier, "verifier cannot be null");
        this.sessionFactory = checkNotNull(sessionFactory, "sessionFactory cannot be null");

        final KeyPair kp = new KeyPair(pairing.getPublicKey(), pairing.getPrivateKey());
        final byte[] commit = pairing.getService().getCommitment();
        prover = new NewSigmaProver(VERSION_1_0, kp, null, verifier, commit, null);
    }

    /**
     * Get the concrete continuous prover for this session.
     *
     * @param verifier         The continuous verifier for this session.
     * @param session          The session.
     * @param continuousClient callbacks triggered when the session state changes.
     * @param scheduler        Schedule interface, the implementation of which should call
     *                         updateVerifier on the given prover within the time specified.
     * @param pollThread       The {@link Executor} thread to use to maintain the continuous
     *                         session.
     * @return The {@link ContinuousProver} for the session.
     */
    public ContinuousProver getContinuousProver(
        final IContinuousVerifier verifier,
        final Session session,
        final ProverStateChangeNotificationInterface continuousClient,
        final SchedulerInterface scheduler,
        final Executor pollThread) {
        if (sequenceNumber.isPresent()) {
            return new ContinuousProver(
                session, verifier, continuousClient, scheduler, sequenceNumber.get(), pollThread);
        } else {
            throw new IllegalStateException("verifier has not assigned a sequence number");
        }
    }

    /**
     * Start the prover session.
     *
     * @return The session started.
     * @throws CryptoRuntimeException in case a crypto error is thrown during the session execution.
     */
    public Session startSession() throws CryptoRuntimeException {
        try {
            // Use actual new prover instance. Return value signals whether continuous is supported
            // or not.
            final boolean continuous = prover.prove();

            // Wrap extra received data in input stream
            LengthPrependedDataInputStream los = new LengthPrependedDataInputStream(
                new DataInputStream(new ByteArrayInputStream(prover.getReceivedExtraData())));

            // Read auth token
            final byte[] authTokenBytes = los.readVariableLengthByteArray();
            final AuthToken authToken = AuthTokenFactory.fromByteArray(authTokenBytes);

            if (continuous) {
                // Read reauth state, sequence number and timeout as well
                ReauthState state;
                try {
                    state = ReauthState.fromByte(los.readByte());
                } catch (InvalidReauthStateIndexException e) {
                    return Session.newInstanceInError(
                        sessionFactory, pairing, Session.Error.SERVICE_REPORTED_ERROR);
                }
                sequenceNumber = Optional.of(
                    SequenceNumber.fromByteArray(los.readVariableLengthByteArray()));
                final int timeout = los.readInt();

                switch (state) {
                    case CONTINUE:
                        return Session.newInstanceActive(
                            sessionFactory,
                            Integer.toString(prover.getVerifierSessionId()),
                            prover.getSharedKey(),
                            pairing,
                            authToken);
                    case PAUSE:
                        return Session.newInstancePaused(
                            sessionFactory,
                            Integer.toString(prover.getVerifierSessionId()),
                            prover.getSharedKey(),
                            pairing,
                            authToken);
                    case STOP:
                        return Session.newInstanceClosed(
                            sessionFactory,
                            Integer.toString(prover.getVerifierSessionId()),
                            pairing,
                            authToken);
                    case ERROR:
                    default:
                        return Session.newInstanceInError(
                            sessionFactory, pairing, Session.Error.SERVICE_REPORTED_ERROR);
                }
            } else {
                return Session.newInstanceClosed(
                    sessionFactory,
                    Integer.toString(prover.getVerifierSessionId()),
                    pairing,
                    authToken);
            }
        } catch (IOException e) {
            fail(e);
            return Session.newInstanceInError(
                sessionFactory, pairing, Session.Error.IO_EXCEPTION);
        } catch (ProverAuthRejectedException e) {
            fail(e);
            return Session.newInstanceInError(
                sessionFactory, pairing, Session.Error.SERVICE_REPORTED_ERROR);
        } catch (ProtocolViolationException e) {
            fail(e);
            // Not really an appropriate session error state, but best there is at the moment
            return Session.newInstanceInError(
                sessionFactory, pairing, Session.Error.SERVICE_REPORTED_ERROR);
        } catch (VerifierAuthFailedException e) {
            fail(e);
            return Session.newInstanceInError(
                sessionFactory, pairing, Session.Error.SERVICE_AUTHENTICATION_FAILURE);
        }
    }

    /**
     * Get the current sequence number.
     *
     * @return the sequence number.
     */
    public SequenceNumber getSequenceNumber() {
        if (sequenceNumber.isPresent()) {
            return sequenceNumber.get();
        } else {
            throw new IllegalStateException("verifier has not assigned a sequence number");
        }
    }

    /**
     * Log the reason for the session failing.
     *
     * @param e The exception that caused the failure.
     */
    private void fail(final Exception e) {
        LOGGER.debug("Authentication to service failed", e);
    }

    /**
     * Log the reason for the session failing.
     *
     * @param reason A description of the reason for the session failing.
     */
    private void fail(final String reason) {
        LOGGER.debug(reason);
    }
}
