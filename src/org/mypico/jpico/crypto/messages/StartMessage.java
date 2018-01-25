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


package org.mypico.jpico.crypto.messages;

import com.google.common.base.Objects;

import java.security.PublicKey;
import java.util.Arrays;

import org.mypico.jpico.crypto.Nonce;

/**
 * The first message of the SIGMA-I protocol, which is sent from the Pico to the service.
 * <p>
 * A <code>StartMessage</code> contains two items:
 * <ul>
 * <li><code>picoEphemeralPublicKey</code> - A Diffie-Hellman exponential which will be combined
 * with another one from the service to form the symmetric keys for this session.
 * <li><code>picoNonce</code> - A nonce to ensure freshness of the service's response.</li>
 * </ul>
 * <p>
 * This message does not have an encrypted form, all fields are sent in the clear.
 * <p>
 * The next message in the protocol is the {@link ServiceAuthMessage}.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public final class StartMessage extends Message {

    private final byte picoVersion;
    private final PublicKey picoEphemeralPublicKey;
    private final Nonce picoNonce;

    /**
     * Constructor.
     *
     * @param picoVersion            The protocol version number.
     * @param picoEphemeralPublicKey The ephemeral public key (per-session) of the prover (Pico).
     * @param picoNonce              The Pico's session nonce.
     */
    StartMessage(byte picoVersion, PublicKey picoEphemeralPublicKey, Nonce picoNonce) {
        this.picoVersion = picoVersion;
        this.picoEphemeralPublicKey = picoEphemeralPublicKey;
        this.picoNonce = picoNonce;
    }

    /**
     * The Pico's "Pico Protocol" version.
     *
     * @return a byte representing the protocol version number
     */
    public byte getPicoVersion() {
        return picoVersion;
    }

    /**
     * Get the ephemral (per-session) public identity key of the prover (Pico).
     *
     * @return the Pico's ephemeral public key.
     */
    public PublicKey getPicoEphemeralPublicKey() {
        return picoEphemeralPublicKey;
    }

    /**
     * Get the Pico's session nonce used for this exchange.
     *
     * @return the Pico session nonce.
     */
    public Nonce getPicoNonce() {
        return picoNonce;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof StartMessage) {
            StartMessage other = (StartMessage) obj;
            return Arrays.equals(this.picoEphemeralPublicKey.getEncoded(),
                other.picoEphemeralPublicKey.getEncoded())
                && this.picoNonce.equals(other.picoNonce);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(picoVersion, picoEphemeralPublicKey, picoNonce);
    }

    /**
     * Retrun an instance of the <code>StartMessage</code>.
     *
     * @param picoVersion            The protocol version number.
     * @param picoEphemeralPublicKey The ephemeral public key (per-session) of the prover (Pico).
     * @param picoNonce              The Pico's session nonce.
     * @return the message object.
     */
    public static final StartMessage getInstance(
        byte picoVersion, PublicKey picoEphemeralPublicKey, Nonce picoNonce) {
        return new StartMessage(picoVersion, picoEphemeralPublicKey, picoNonce);
    }
}
