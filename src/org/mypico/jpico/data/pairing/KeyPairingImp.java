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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface of concrete implementations underlying {@link KeyPairing} instances.
 * <p>
 * <p>
 * This interface is part of a <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge
 * pattern</a>. Each <code>KeyPairing</code> instance has a reference to a concrete
 * {@link KeyPairingImp} instance. See {@link org.mypico.jpico.test.data.pairing} package documentation
 * for more information on this pattern.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see KeyPairing
 * @see KeyPairingImpFactory
 */
public interface KeyPairingImp extends PairingImp {

    /**
     * Get the public key of the asymmetric key pair.
     *
     * @return the public key.
     */
    PublicKey getPublicKey();

    /**
     * Get the private key of the asymmetric key pair.
     *
     * @return the public key.
     */
    PrivateKey getPrivateKey();

    /**
     * Get the extra data associated with the key pairing.
     *
     * @return the extra data.
     */
    String getExtraData();
}
