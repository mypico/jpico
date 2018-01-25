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


package org.mypico.jpico.backup;

/**
 * Abstract class representing BackupKey exceptions.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public abstract class BackupFileException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Default constructor.
     */
    public BackupFileException() {
        super();
    }

    /**
     * Constructor that stores a description for the exception.
     *
     * @param description exception description.
     */
    public BackupFileException(final String description) {
        super(description);
    }
}