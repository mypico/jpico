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

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A DataInputStream which provides an option to read a byte array which has been prepended by its
 * length in bytes.
 * <p>
 * NB: Does not need to be Destroyable, as long as the underlying stream source is destroyed.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @see LengthPrependedDataOutputStream
 * @see DestroyableByteArray
 */
public class LengthPrependedDataInputStream extends DataInputStream {

    public final static int maxLength = 200 * 1024; // 200K

    /**
     * Constructor.
     *
     * @param in The input stream to read data from (that isn't length-prepended).
     */
    public LengthPrependedDataInputStream(InputStream in) {
        super(in);
    }

    /**
     * Read in a byte array from the stream.
     * <p>
     * First the length will be read. The stream will then read in the amount of data specified by
     * the length read from the stream.
     *
     * @return the data read (without the length prefix).
     * @throws IOException in case an error occurs reading the data from the stream.
     */
    public byte[] readVariableLengthByteArray() throws IOException {
        int length = readInt();
        if (length < 0 || length > maxLength) {
            throw new IOException(String.format(
                "Invalid length of byte array (%d)", length));
        }
        byte[] bytes = new byte[length];
        readFully(bytes); // May also raise an IOException.
        return bytes;
    }

    /**
     * Read the bytes from the data stream as a destroyable object. The data will not include the
     * length prefix read from the stream.
     *
     * @return a {@link DestroyableByteArray} containing the data read from the stream.
     * @throws IOException
     * @see DestroyableByteArray
     */
    public DestroyableByteArray readDestroyableVariableLengthByteArray()
        throws IOException {
        return new DestroyableByteArray(readVariableLengthByteArray());
    }

}
