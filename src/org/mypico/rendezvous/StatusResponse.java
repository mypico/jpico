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
import java.net.HttpURLConnection;

import org.apache.commons.io.IOUtils;

import com.google.gson.Gson;


final class StatusResponse {
    // Response codes
    public static final int CLOSED = -1;
    public static final int OK = 0;
    public static final int TIMED_OUT = 2;

    public static StatusResponse fromConnection(HttpURLConnection connection)
        throws IOException {
        // Check response code
        if (connection.getResponseCode() != 200) {
            throw new IOException("response code was not 200 OK");
        }
        // Check content is non-empty
        if (connection.getContentLength() <= 0) {
            throw new IOException("response was empty response");
        }
        // Check content is JSON-encoded
        if (!connection.getContentType().equals("application/json")) {
            throw new IOException("status response was not JSON-encoded");
        }
        // TODO replace these checks with guava preconditions methods?

        // Read bytes
        byte[] responseBytes = new byte[connection.getContentLength()];
        IOUtils.readFully(connection.getInputStream(), responseBytes);

        final String responseString = new String(responseBytes, "UTF-8");
        return new Gson().fromJson(responseString, StatusResponse.class);
    }

    private StatusResponse() {
        super();
    }

    public int code;
    public String status;
    public String message;

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }
}
