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

import org.mypico.jpico.crypto.messages.EncPicoAuthMessage;
import org.mypico.jpico.crypto.messages.EncServiceAuthMessage;
import org.mypico.jpico.crypto.messages.EncStatusMessage;
import org.mypico.jpico.crypto.messages.StartMessage;

/**
 * Callback interface to be implemented by the Pico server when the client service application
 * needs to be notified of authentication events.
 * <p>
 * <p>As an example, consider a web site using Pico authentication. The service consists of two
 * separate components:
 * <p>
 * <ol>
 * <li>The web server serving the web site itself which is the "client service application" and
 * is what the user interacts with.</li>
 * <li>The Pico server which communicates with the users' Picos.</li>
 * </ol>
 * <p>
 * <p>In this case the Pico server would include a concrete SigmaClientInterface implementation
 * capable of notifying the web server of the relevant events using some kind of inter-process
 * communication mechanism.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see ContinuousVerifier#clientInterface
 * @see org.mypico.jpico.crypto.IContinuousVerifier.Client
 */
public interface ISigmaVerifier {
    /**
     * Callback interface to be implemented by the Pico server when the client service application
     * needs to be notified of authentication events.
     * <p>
     * <p>As an example, consider a web site using Pico authentication. The service consists of two
     * separate components:
     * <p>
     * <ol>
     * <li>The web server serving the web site itself which is the "client service application" and
     * is what the user interacts with.</li>
     * <li>The Pico server which communicates with the users' Picos.</li>
     * </ol>
     * <p>
     * <p>In this case the Pico server would include a concrete SigmaClientInterface implementation
     * capable of notifying the web server of the relevant events using some kind of inter-process
     * communication mechanism.
     *
     * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
     * @see ContinuousVerifier#clientInterface
     * @see org.mypico.jpico.crypto.IContinuousVerifier.Client
     */
    public interface Client {

        public static class ClientAuthorisation {
            // Singletons for simple common return values
            private static final ClientAuthorisation emptyAccept =
                new ClientAuthorisation(true, null);
            private static final ClientAuthorisation reject =
                new ClientAuthorisation(false, null);

            public static ClientAuthorisation accept(byte[] extraData) {
                return new ClientAuthorisation(true, extraData);
            }

            public static ClientAuthorisation accept() {
                return emptyAccept;
            }

            public static ClientAuthorisation reject() {
                return reject;
            }

            private final boolean authorised;
            private final byte[] extraData;

            private ClientAuthorisation(boolean a, byte[] d) {
                authorised = a;
                extraData = d;
            }

            public boolean authorised() {
                return authorised;
            }

            public byte[] extraData() {
                return extraData;
            }
        }

        public ClientAuthorisation onAuthenticate(PublicKey picoPublicKey, byte[] receivedExtraData)
            throws IOException;
    }

    /**
     * Start an authentication session with the verifier by sending a {@link StartMessage}.
     *
     * @param msg the Start Message to be processed by the verifier.
     * @return the verifier's response. This method never returns <code>null</code>.
     * @throws ProtocolViolationException if the prover violated the protocol.
     * @throws IOException                in case a network error occurs during the sending of the start message.
     */
    public abstract EncServiceAuthMessage start(StartMessage msg)
        throws IOException, ProtocolViolationException;

    /**
     * Authenticate to the verifier by sending an {@link EncPicoAuthMessage}.
     *
     * @param msg the encrypted Prover Authentication Message to be processed by the verifier.
     * @return the verifier's response.
     * @throws ProtocolViolationException if the prover violated the protocol.
     * @throws IOException                in case a network error occurs during the receiving of the start message.
     */
    public abstract EncStatusMessage authenticate(EncPicoAuthMessage msg)
        throws IOException, ProtocolViolationException;
}
