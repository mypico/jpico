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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class RendezvousChannel {

    private final URL url;
    private volatile boolean isOpen = true;

    private RendezvousInputStream inputStream = null;
    private RendezvousOutputStream outputStream = null;

    private int timeout = 10000;

    public RendezvousChannel(URL url) {
        this.url = url;
    }

    public RendezvousChannel(URL url, int timeout) {
        this(url);
        setTimeout(timeout);
    }


    public URL getUrl() {
        return url;
    }

    public void setTimeout(int ms) {
        timeout = ms;
    }

    synchronized public InputStream getInputStream() {
        if (isOpen && inputStream == null) {
            inputStream = new RendezvousInputStream(this);
        }
        return inputStream;
    }

    synchronized public OutputStream getOutputStream() {
        if (isOpen && outputStream == null) {
            outputStream = new RendezvousOutputStream(this);
        }
        return outputStream;
    }

    public void close() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        if (timeout != -1) {
            connection.setReadTimeout(timeout);
        }
        connection.setRequestMethod("DELETE");

        // Make request...
        final int responseCode = connection.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            isOpen = false;
            if (outputStream != null) {
                outputStream.close();
                outputStream = null;
            } else if (inputStream != null) {
                inputStream.close();
                inputStream = null;
            }
        } else if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
            throw new IOException("no such channel: " + url);
        } else {
            throw new IOException(String.format(
                "inavlid HTTP response code: %d %s",
                responseCode,
                connection.getResponseMessage()));
        }
    }

    HttpURLConnection attemptRead() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        if (timeout != -1) {
            connection.setReadTimeout(timeout);
        }

        // Make request...
        final int responseCode = connection.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            return connection;
        } else if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
            throw new IOException("no such channel: " + url);
        } else {
            throw new IOException(String.format(
                "inavlid HTTP response code: %d %s",
                responseCode,
                connection.getResponseMessage()));
        }
    }

    HttpURLConnection attemptWrite(byte[] bytes) throws IOException {
        // Do request
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        if (timeout != -1) {
            connection.setReadTimeout(timeout);
        }

        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/octet-stream");
        connection.setRequestProperty("Content-Length", Integer.toString(bytes.length));

        connection.setDoOutput(true);
        OutputStream os = null;
        try {
            os = connection.getOutputStream();
            os.write(bytes);
            os.flush();
        } finally {
            if (os != null) {
                os.close();
            }
        }

        // Make request...
        final int responseCode = connection.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            return connection;
        } else if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
            throw new IOException("no such channel: " + url);
        } else {
            throw new IOException(String.format(
                "inavlid HTTP response code: %d %s",
                responseCode,
                connection.getResponseMessage()));
        }
    }
}
