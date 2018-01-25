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

import javax.security.auth.Destroyable;

import org.mypico.jpico.crypto.ContinuousProver.ProverStateChangeNotificationInterface;
import org.mypico.jpico.crypto.ContinuousProver.SchedulerInterface;
import org.mypico.jpico.data.session.Session;

/**
 * Interface to be implemented by provers.
 * <p>
 * See for example the {@link LensProver} for a concrete implementation.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public interface Prover extends Destroyable {

    /**
     * A prover should implement this method to return the {@link ContinuousProver} in use.
     *
     * @param session                                The session id.
     * @param proverStateChangeNotificationInterface callback interface for notifying interested
     *                                               parties about protocol state changes.
     * @param schedulerInterface                     Schedule interface, the implementation of which should call
     *                                               updateVerifier on the given prover within the time specified.
     * @return The concrete {@link ContinuousProver} instance.
     */
    public ContinuousProver getContinuousProver(
        final Session session,
        final ProverStateChangeNotificationInterface
            proverStateChangeNotificationInterface,
        final SchedulerInterface schedulerInterface);

    /**
     * Start the prover session.
     *
     * @return The session started.
     * @throws CryptoRuntimeException in case a crypto error is thrown during the session execution.
     */
    public Session startSession() throws CryptoRuntimeException;

}
