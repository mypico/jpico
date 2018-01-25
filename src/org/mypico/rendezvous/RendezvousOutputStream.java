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


package org.mypico.rendezvous;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;

public class RendezvousOutputStream extends OutputStream implements InterruptibleStream {

    private final RendezvousChannel rendezvousChannel;
    private volatile boolean isOpen = true;

    public RendezvousOutputStream(RendezvousChannel rendezvousChannel) {
        this.rendezvousChannel = rendezvousChannel;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        // Get the desired bytes
        byte[] bytes;
        if (off > 0 || len < b.length) {
            bytes = new byte[len - off];
            System.arraycopy(b, off, bytes, 0, len);
        } else {
            bytes = b;
        }

        while (isOpen) {
            HttpURLConnection connection = rendezvousChannel.attemptWrite(bytes);
            // Would have thrown an IOException by this point if response was not 200 OK

            StatusResponse response = StatusResponse.fromConnection(connection);
            if (response.code == 0) {
                // Write was successful, finish
                return;
            } else if (response.code == StatusResponse.TIMED_OUT) {
                // Timed out, try again, unless closed by another thread.
                // Might well benefit from implementing a java.nio Channel
                // subclasses instead of the input and output streams
            } else {
                // An error occured (rendezvous layer i.e. not HTTP 404)
                throw new IOException(String.format(
                    "inavlid rendezvous response code: %d %s",
                    response.code,
                    response.message));
            }
        }
        // Close the Rendezvous Point
        throw new IOException("write to rendezvous which has been closed");
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[]{(byte) b}, 0, 1);
    }

    /**
     * Closes the output stream, any writes that have not been acknowledged will be cancelled when
     * they time out.
     */
    @Override
    public void close() throws IOException {
        isOpen = false;
        super.close();
    }

    public boolean isOpen() {
        return isOpen;
    }
}
