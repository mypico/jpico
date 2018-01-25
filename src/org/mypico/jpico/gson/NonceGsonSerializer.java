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

import org.mypico.jpico.crypto.Nonce;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

/**
 * Custom Gson serializer and deserializer for {@link Nonce} instances.
 *
 * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public final class NonceGsonSerializer implements JsonSerializer<Nonce>,
    JsonDeserializer<Nonce> {

    @Override
    public Nonce deserialize(final JsonElement json, final Type type,
                             final JsonDeserializationContext context) throws JsonParseException {
        final byte[] valueBytes = context.deserialize(json, byte[].class);
        if (valueBytes == null || valueBytes.length == 0)
            throw new JsonParseException("Invalid nonce");
        return Nonce.getInstance(valueBytes);
    }

    @Override
    public JsonElement serialize(final Nonce nonce, final Type type,
                                 final JsonSerializationContext context) {

        // check the nonce hasn't been destroyed, in which case it presumably shouldn't be used again
        if (nonce.isDestroyed()) {
            throw new IllegalStateException(
                "A destroyed Nonce can't be serialized");
        }

        return context.serialize(nonce.getValue(), byte[].class);
    }

}
