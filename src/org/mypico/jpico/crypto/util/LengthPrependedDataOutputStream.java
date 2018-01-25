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

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A DataOutputStream which writes a byte array which has been prepended by its
 * length in bytes.
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see LengthPrependedDataInputStream
 */
public class LengthPrependedDataOutputStream extends DataOutputStream {

    /**
     * Constructor.
     *
     * @param out The output stream to use to write data to (that isn't length-prepended).
     */
    public LengthPrependedDataOutputStream(OutputStream out) {
        super(out);
    }

    /**
     * Write out a byte array t the stream.
     * <p>
     * First the length will be written. The stream will then write out the amount of data
     * specified by the length.
     *
     * @param b The bytes to write.
     * @throws IOException in case an error occurs writing data to the stream.
     */
    public void writeVariableLengthByteArray(byte[] b) throws IOException {
        checkNotNull(b, "b cannot be null");
        if (b.length > LengthPrependedDataInputStream.maxLength)
            throw new IOException("Byte array too large " + b.length + " (max=" + LengthPrependedDataInputStream.maxLength + ")");
        writeInt(b.length);
        write(b);
    }
}
