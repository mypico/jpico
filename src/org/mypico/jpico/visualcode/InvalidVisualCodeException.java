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


package org.mypico.jpico.visualcode;

/**
 * Invalid visual code exception.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class InvalidVisualCodeException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructor.
     */
    public InvalidVisualCodeException() {
        super();
    }

    /**
     * Consructor.
     *
     * @param message A human-readable message describing the error.
     */
    public InvalidVisualCodeException(final String message) {
        super(message);
    }

    /**
     * Consructor.
     *
     * @param cause The underlying cause of the error.
     */
    public InvalidVisualCodeException(Throwable cause) {
        super(cause);
    }

    /**
     * Consructor.
     *
     * @param message A human-readable message describing the error.
     * @param cause   The underlying cause of the error.
     */
    public InvalidVisualCodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
