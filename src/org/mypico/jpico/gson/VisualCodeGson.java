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
import java.security.PublicKey;
import java.util.Map;
import java.util.TreeMap;

import org.mypico.jpico.crypto.Nonce;
import org.mypico.jpico.visualcode.DelegatePairingVisualCode;
import org.mypico.jpico.visualcode.InvalidVisualCodeException;
import org.mypico.jpico.visualcode.KeyAuthenticationVisualCode;
import org.mypico.jpico.visualcode.KeyPairingVisualCode;
import org.mypico.jpico.visualcode.LensAuthenticationVisualCode;
import org.mypico.jpico.visualcode.LensPairingVisualCode;
import org.mypico.jpico.visualcode.TerminalPairingVisualCode;
import org.mypico.jpico.visualcode.VisualCode;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

/**
 * Convenience class which provides a custom {@link com.google.gson.Gson} instance for
 * JSON-serializing {@link VisualCode} objects.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @author Seb Aebischer <seb.aebischer@cl.cam.ac.uk>
 */
public class VisualCodeGson {

    /**
     * The custom <code>Gson</code> instance.
     */
    public static final Gson gson = new GsonBuilder()
        .registerTypeAdapter(VisualCode.class, new VisualCodeGsonSerializer())
        .registerTypeAdapter(Nonce.class, new NonceGsonSerializer())
        .registerTypeAdapter(byte[].class, new ByteArrayGsonSerializer())
        .registerTypeAdapter(PublicKey.class, new PublicKeyGsonSerializer())
        .disableHtmlEscaping()
        .create();

    /**
     * Create a customised {@link VisualCode} serialiser that uses the given map of classes instead
     * of the default JPico {@link VisualCode} subclasses.
     * <p>
     * For efficiency you should call this only once per map and keep the returned Gson, rather than
     * calling every time you need to (de)serialise something with the given map.
     * <p>
     * The map must contain entries for all six {@code VisualCode} types:
     * * KeyPairingVisualCode.TYPE
     * * KeyAuthenticationVisualCode.TYPE
     * * LensPairingVisualCode.TYPE
     * * LensAuthenticationVisualCode.TYPE
     * * TerminalPairingVisualCode.TYPE
     * * DelegatePairingVisualCode.TYPE
     *
     * @param map The map from {@code VisualCode} type to {@code VisualCode} subclass.
     * @return The customised {@link Gson} instance.
     */
    public static Gson custom(Map<String, Class<? extends VisualCode>> map) {
        // verify that every type is present
        if (!(map.containsKey(KeyPairingVisualCode.TYPE) &&
            map.containsKey(KeyAuthenticationVisualCode.TYPE) &&
            map.containsKey(LensPairingVisualCode.TYPE) &&
            map.containsKey(LensAuthenticationVisualCode.TYPE) &&
            map.containsKey(TerminalPairingVisualCode.TYPE) &&
            map.containsKey(DelegatePairingVisualCode.TYPE)))
            throw new IllegalArgumentException("Map does not contain entries for every code type");
        // create the Gson
        return new GsonBuilder()
            .registerTypeAdapter(VisualCode.class, new VisualCodeGsonSerializer(map))
            .registerTypeAdapter(Nonce.class, new NonceGsonSerializer())
            .registerTypeAdapter(byte[].class, new ByteArrayGsonSerializer())
            .registerTypeAdapter(PublicKey.class, new PublicKeyGsonSerializer())
            .disableHtmlEscaping()
            .create();
    }

}

/**
 * Custom Gson serializer and deserializer for {@link VisualCode} subclass instances.
 *
 * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
 * @author Graeme Jenkinson &lt;gcj21@cl.cam.ac.uk&gt;
 * @author Seb Aebischer &lt;seb.aebischer@cl.cam.ac.uk&gt;
 */
final class VisualCodeGsonSerializer implements JsonSerializer<VisualCode>,
    JsonDeserializer<VisualCode> {

    private static Map<String, Class<? extends VisualCode>> defaultMap =
        new TreeMap<String, Class<? extends VisualCode>>();

    static {
        defaultMap.put(LensAuthenticationVisualCode.TYPE, LensAuthenticationVisualCode.class);
        defaultMap.put(LensPairingVisualCode.TYPE, LensPairingVisualCode.class);
        defaultMap.put(KeyPairingVisualCode.TYPE, KeyPairingVisualCode.class);
        defaultMap.put(KeyAuthenticationVisualCode.TYPE, KeyAuthenticationVisualCode.class);
        defaultMap.put(TerminalPairingVisualCode.TYPE, TerminalPairingVisualCode.class);
        defaultMap.put(DelegatePairingVisualCode.TYPE, DelegatePairingVisualCode.class);
    }

    private final Map<String, Class<? extends VisualCode>> map;

    /**
     * The default constructor will deserialise into the JPico {@link VisualCode} subclasses
     * according to {@link #defaultMap}.
     */
    public VisualCodeGsonSerializer() {
        map = defaultMap;
    }

    /**
     * This constructor allows a custom class mapping to be used, so that {@link VisualCode}
     * subclasses external to JPico can be output.
     */
    public VisualCodeGsonSerializer(Map<String, Class<? extends VisualCode>> map) {
        this.map = map;
    }

    @Override
    public VisualCode deserialize(final JsonElement json, final Type type,
                                  final JsonDeserializationContext context) throws JsonParseException {

        // make sure there is a code type element
        final JsonElement visualCodeTypeObj = json.getAsJsonObject().get("t");
        if (visualCodeTypeObj == null) {
            throw new JsonParseException("Missing visual code type element");
        }

        // Verify whether the VisualCode is a valid type
        final String visualCodeType = visualCodeTypeObj.getAsString();
        if (!map.containsKey(visualCodeType)) {
            throw new JsonParseException("Invalid visual code type: " + visualCodeType);
        } else {
            return context.deserialize(json, map.get(visualCodeType));
        }

    }

    @Override
    public JsonElement serialize(final VisualCode visualCode, final Type type,
                                 final JsonSerializationContext context) {

        // Verify whether the VisualCode is a valid type
        if (!map.containsKey(visualCode.getType())) {
            throw new JsonParseException("VisualCode type is invalid");
        } else {
            return context.serialize(visualCode, map.get(visualCode.getType()));
        }
    }
}
