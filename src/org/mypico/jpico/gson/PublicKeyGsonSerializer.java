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


// Copyright University of Cambridge, 2013

package org.mypico.jpico.gson;

import java.lang.reflect.Type;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.mypico.jpico.crypto.CryptoFactory;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

/**
 * Custom Gson serializer and deserializer for {@link PublicKey} instances.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public final class PublicKeyGsonSerializer
    implements JsonSerializer<PublicKey>, JsonDeserializer<PublicKey> {

    private static final KeyFactory kf = CryptoFactory.INSTANCE.ecKeyFactory();

    @Override
    public PublicKey deserialize(
        final JsonElement json, final Type type, final JsonDeserializationContext context)
        throws JsonParseException {
        byte[] keyBytes = context.deserialize(json, byte[].class);
        if (keyBytes == null || keyBytes.length == 0) {
            throw new JsonParseException("Invalid public key");
        }
        try {
            return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (IllegalArgumentException e) {
            throw new JsonParseException("Invalid public key");
        } catch (InvalidKeySpecException e) {
            throw new JsonParseException(e);
        }

    }

    @Override
    public JsonElement serialize(
        final PublicKey key, final Type type, final JsonSerializationContext context) {
        return context.serialize(key.getEncoded(), byte[].class);
    }
}
