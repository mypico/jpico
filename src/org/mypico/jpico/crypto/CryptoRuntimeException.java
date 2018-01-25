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
 * Unchecked exception for re-throwing cryptographic exceptions which are caused by configuration
 * errors. Exceptions of this type should never be raised in production code.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class CryptoRuntimeException extends RuntimeException {

    private static final long serialVersionUID = -4102778298152030517L;

    /**
     * Constructor.
     */
    public CryptoRuntimeException() {
        super();
    }

    /**
     * Constructor.
     *
     * @param message The exception message.
     * @param cause   The prior cause for the exception.
     */
    public CryptoRuntimeException(
        final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor.
     *
     * @param message The exception message.
     */
    public CryptoRuntimeException(final String message) {
        super(message);
    }

    /**
     * Constructor.
     *
     * @param cause The prior cause for the exception.
     */
    public CryptoRuntimeException(final Throwable cause) {
        super(cause);
    }
}
