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

import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

import org.mypico.jpico.crypto.IContinuousVerifier;
import org.mypico.jpico.crypto.ProtocolViolationException;
import org.mypico.jpico.crypto.ServiceSigmaVerifier;

import com.google.common.base.Optional;

/**
 * Provides a socket-based communication channel for performing the SIGMA-I protocol. This isn't
 * currently used by the Android app.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see MessageSerializer
 */
public class BaseSocketServer implements Runnable {

    public interface BaseSocketCallbacks {
        void onConnectError(IOException e);

        void onConnect(int clientNum, Socket socket);

        void onDisconnect(int clientNum);

        void onUnexpectedDisconnect(int clientNum, EOFException e);

        void onIOError(int clientNum, IOException e);

        void onProtocolViolation(int clientNum, ProtocolViolationException e);
    }

    private final ServerSocket socket;
    private final KeyPair keyPair;
    private final MessageSerializer serializer;
    private final ServiceSigmaVerifier.Client sigmaClient;

    private final boolean continuous;
    private final Optional<IContinuousVerifier.Client> continuousClient;
    private final Optional<BaseSocketCallbacks> callbacks;

    /**
     * Constructor.
     *
     * @param socket      The socket to use as a channel.
     * @param keyPair     The keypair to use for authentication.
     * @param serializer  A message serializer compatible with the remote verifier.
     * @param sigmaClient a Sigma Client implementation.
     */
    public BaseSocketServer(
        final ServerSocket socket,
        final KeyPair keyPair,
        final MessageSerializer serializer,
        final ServiceSigmaVerifier.Client sigmaClient) {
        this(socket, keyPair, serializer, sigmaClient, null, null);
    }

    /**
     * Constructor.
     *
     * @param socket      The socket to use as a channel.
     * @param keyPair     The keypair to use for authentication.
     * @param serializer  A message serializer compatible with the remote verifier.
     * @param sigmaClient A Sigma Client implementation.
     * @param callbacks   A set of <code>BaseSocketCallbacks</code> callbacks that are triggered at
     *                    various points in the protocol (e.g. connect, disconnect and errors).
     */
    public BaseSocketServer(
        final ServerSocket socket,
        final KeyPair keyPair,
        final MessageSerializer serializer,
        final ServiceSigmaVerifier.Client sigmaClient,
        final BaseSocketCallbacks callbacks) {
        this(socket, keyPair, serializer, sigmaClient, null, callbacks);
    }

    /**
     * Constructor.
     *
     * @param socket           The socket to use as a channel.
     * @param keyPair          The keypair to use for authentication.
     * @param serializer       A message serializer compatible with the remote verifier.
     * @param sigmaClient      A Sigma Client implementation.
     * @param continuousClient For performing continuous authentication.
     */
    public BaseSocketServer(
        final ServerSocket socket,
        final KeyPair keyPair,
        final MessageSerializer serializer,
        final ServiceSigmaVerifier.Client sigmaClient,
        final IContinuousVerifier.Client continuousClient) {
        this(socket, keyPair, serializer, sigmaClient, continuousClient, null);
    }

    /**
     * Constructor.
     *
     * @param socket           The socket to use as a channel.
     * @param keyPair          The keypair to use for authentication.
     * @param serializer       A message serializer compatible with the remote verifier.
     * @param sigmaClient      A Sigma Client implementation.
     * @param callbacks        A set of <code>BaseSocketCallbacks</code> callbacks that are triggered at
     *                         various points in the protocol (e.g. connect, disconnect and errors).
     * @param continuousClient For performing continuous authentication.
     */
    public BaseSocketServer(
        final ServerSocket socket,
        final KeyPair keyPair,
        final MessageSerializer serializer,
        final ServiceSigmaVerifier.Client sigmaClient,
        final IContinuousVerifier.Client continuousClient,
        final BaseSocketCallbacks callbacks) {
        this.socket = checkNotNull(socket, "socket cannot be null");
        this.keyPair = checkNotNull(keyPair, "keyPair cannot be null");
        this.serializer = checkNotNull(serializer, "serializer cannot be null");
        this.sigmaClient = checkNotNull(sigmaClient, "sigmaClient cannot be null");

        // continuousClient being null just results in there being no continuous auth
        this.continuous = (continuousClient != null);
        this.continuousClient = Optional.fromNullable(continuousClient);

        // May or may not have callbacks
        this.callbacks = Optional.fromNullable(callbacks);
    }

    @Override
    public void run() {
        int numClients = 0;

        while (true) {
            final Socket connectedSocket;
            final int clientNum;

            try {
                // Attempt to accept connection from client
                connectedSocket = socket.accept();

                // ...accept succeeded
                clientNum = ++numClients;
                if (callbacks.isPresent()) {
                    callbacks.get().onConnect(clientNum, connectedSocket);
                }
            } catch (IOException e) {
                // ...accept failed
                if (callbacks.isPresent()) {
                    callbacks.get().onConnectError(e);
                }
                break;
            }

            // Construct a verifier for the connected client
            final ServiceSigmaVerifier verifier = new ServiceSigmaVerifier(
                keyPair, sigmaClient, continuous);

            // Construct handler to manager the transfer of messages between this verifier and the
            // remote client:
            final SocketSigmaHandler handler = new SocketSigmaHandler(
                connectedSocket, serializer, verifier, continuous);

            // wrap into a runnable...
            final Runnable r = new Runnable() {
                @Override
                public void run() {
                    try {
                        // Call the sigma client handler to carry out the initial authentication
                        handler.call();

                        // Now create and call a continuous handler if continuous is turned on
                        if (continuous) {
                            final IContinuousVerifier continuousVerifier =
                                verifier.getContinuousVerifier(continuousClient.get());
                            final SocketContinuousHandler continuousHandler =
                                new SocketContinuousHandler(
                                    connectedSocket, serializer, continuousVerifier);
                            continuousHandler.call();
                        }

                        // Finished, client has disconnected (properly)
                        if (callbacks.isPresent()) {
                            callbacks.get().onDisconnect(clientNum);
                        }
                    } catch (EOFException e) {
                        if (callbacks.isPresent()) {
                            callbacks.get().onUnexpectedDisconnect(clientNum, e);
                        }
                    } catch (IOException e) {
                        if (callbacks.isPresent()) {
                            callbacks.get().onIOError(clientNum, e);
                        }
                    } catch (ProtocolViolationException e) {
                        if (callbacks.isPresent()) {
                            callbacks.get().onProtocolViolation(clientNum, e);
                        }
                    }
                }
            };

            // and run in its own thread
            new Thread(r).start();
        }
    }
}
