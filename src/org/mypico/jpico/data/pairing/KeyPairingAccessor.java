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

import java.io.IOException;
import java.util.List;

/**
 * Interface of an "accessor" which returns {@link KeyPairing} instances saved in a data store.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see KeyPairing
 */
public interface KeyPairingAccessor {

    /**
     * Query the store for a key pairing with a given ID.
     *
     * @param pairingId ID to query for.
     * @return <code>KeyPairing</code> instance with matching ID or <code>null</code> if none could
     * be found.
     * @throws IOException if an <code>IOException</code> occurred whilst querying the data store.
     */
    public KeyPairing getKeyPairingById(int pairingId) throws IOException;

    /**
     * Query the store for key pairings with a service with a given commitment.
     *
     * @param commitment service commitment to query for.
     * @return <code>KeyPairing</code> instances with service with matching public key.
     * @throws IOException if an <code>IOException</code> occurred whilst querying the data store.
     */
    public List<KeyPairing> getKeyPairingsByServiceCommitment(
        byte[] commitment) throws IOException;

    /**
     * Get a list of all key pairings in the store.
     *
     * @return all <code>KeyPairing</code> instances.
     * @throws IOException if an <code>IOException</code> occurred whilst querying the data store.
     */
    public List<KeyPairing> getAllKeyPairings() throws IOException;
}
