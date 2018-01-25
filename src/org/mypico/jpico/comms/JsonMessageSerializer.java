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


package org.mypico.jpico.comms;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;

import org.mypico.jpico.crypto.messages.Message;
import org.mypico.jpico.gson.MessageGson;

import com.google.gson.Gson;

/**
 * A <code>MessageSerializer</code> implementation which serializes {@link Message} objects by
 * turning them into JSON.
 * <p>
 * The JSON strings are encoded to byte arrays using the <code>UTF-8</code> character set.
 *
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public class JsonMessageSerializer implements MessageSerializer {

    private static final Gson gson = MessageGson.gson;

    @Override
    public byte[] serialize(Message m, Type type)
        throws UnsupportedEncodingException {
        String jsonString = gson.toJson(m, type);
        return jsonString.getBytes("UTF-8");
    }

    @Override
    public <T extends Message> T deserialize(byte[] bytes, Class<T> classOfT)
        throws UnsupportedEncodingException {
        String jsonString = new String(bytes, "UTF-8");
        return gson.fromJson(jsonString, classOfT);
    }
}
