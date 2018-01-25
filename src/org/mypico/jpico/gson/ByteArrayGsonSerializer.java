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


package org.mypico.jpico.gson;

import java.lang.reflect.Type;

import org.mypico.jpico.comms.org.apache.commons.codec.binary.Base64;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

/**
 * Serialize and deserialie Json strings.
 */
public class ByteArrayGsonSerializer
    implements JsonDeserializer<byte[]>, JsonSerializer<byte[]> {

    @Override
    public JsonElement serialize(
        byte[] b, Type type, JsonSerializationContext context) {
        String s = Base64.encodeBase64String(b);
        return new JsonPrimitive(s);
    }

    @Override
    public byte[] deserialize(
        JsonElement json, Type type, JsonDeserializationContext context)
        throws JsonParseException {
        String s = json.getAsJsonPrimitive().getAsString();
        return Base64.decodeBase64(s);
    }
}
