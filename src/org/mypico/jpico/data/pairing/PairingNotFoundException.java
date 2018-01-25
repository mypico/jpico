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

/**
 * Pairing not found in data store.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public class PairingNotFoundException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Exception thrown to indicate that a {@link Pairing} could not be found.
     */
    public PairingNotFoundException() {
        super();
    }

    /**
     * Exception thrown to indicate that a {@link Pairing} could not be found.
     *
     * @param message A human-readable description of the error.
     */
    public PairingNotFoundException(final String message) {
        super(message);
    }
}
