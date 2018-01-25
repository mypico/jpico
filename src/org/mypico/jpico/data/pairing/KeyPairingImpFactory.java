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


package org.mypico.jpico.data.pairing;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.mypico.jpico.data.service.Service;

/**
 * Interface of a factory which produces concrete {@link KeyPairingImp} instances.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see KeyPairing
 * @see KeyPairingImp
 */
public interface KeyPairingImpFactory {

    /**
     * Get a concrete {@link KeyPairingImp} instance.
     *
     * @param name       The name of the service the key is associated with.
     * @param service    The service the key is associated with.
     * @param publicKey  The public key.
     * @param privateKey The private key.
     * @param extraData  Optional extra data to associate with the key.
     * @return the concrete {@link KeyPairingImp} instance.
     */
    public KeyPairingImp getImp(
        String name,
        Service service,
        PublicKey publicKey,
        PrivateKey privateKey,
        String extraData);

    /**
     * Get a concrete {@link KeyPairingImp} instance.
     *
     * @param name      The name of the service the key is associated with.
     * @param service   The service the key is associated with.
     * @param keyPair   The assymmetric key pair.
     * @param extraData Optional extra data to associate with the key.
     * @return the concrete {@link KeyPairingImp} instance.
     */
    public KeyPairingImp getImp(String name, Service service, KeyPair keyPair, String extraData);

    /**
     * Make a new copy of a concrete {@link KeyPairingImp} instance.
     *
     * @param keyPairing The {@link KeyPairingImp} to copy.
     * @return the new concrete {@link KeyPairingImp} instance.
     */
    public KeyPairingImp getImp(KeyPairing keyPairing);
}
