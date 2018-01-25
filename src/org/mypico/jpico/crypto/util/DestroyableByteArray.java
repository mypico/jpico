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


package org.mypico.jpico.crypto.util;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * A byte array that will zero itself when explicitly destroyed.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public class DestroyableByteArray implements Destroyable {

    private final byte[] array;
    private boolean isDestroyed = false;

    /**
     * Constructor.
     *
     * @param bytes the data to store in the byte array.
     */
    public DestroyableByteArray(byte[] bytes) {
        this.array = bytes;
    }

    /**
     * Convert the byte array into a data stream with the length of the byte array prefixed as an
     * integer onto the front of the stream.
     *
     * @return the length-prepended stream.
     */
    public LengthPrependedDataInputStream getLengthPrependedDataInputStream() {
        ByteArrayInputStream is = new ByteArrayInputStream(array); // Does not
        // copy array
        return new LengthPrependedDataInputStream(is);
    }

    @Override
    public void destroy() throws DestroyFailedException {
        byte zero = 0;
        Arrays.fill(array, zero);
        this.isDestroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return this.isDestroyed;
    }

}
