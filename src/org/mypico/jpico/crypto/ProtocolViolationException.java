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

/**
 * Exceptions thrown in case an error occurs in the SIGMA-I protocol.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class ProtocolViolationException extends Exception {

    private static final long serialVersionUID = 3922332039175403488L;

    /**
     * Constructor.
     */
    public ProtocolViolationException() {
        super();
    }

    /**
     * Constructor.
     *
     * @param message The exception message.
     * @param cause   The prior cause for the exception.
     */
    public ProtocolViolationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor.
     *
     * @param message The exception message.
     */
    public ProtocolViolationException(String message) {
        super(message);
    }

    /**
     * Constructor.
     *
     * @param cause The prior cause for the exception.
     */
    public ProtocolViolationException(Throwable cause) {
        super(cause);
    }
}