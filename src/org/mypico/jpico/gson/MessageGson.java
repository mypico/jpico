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

import java.security.PublicKey;

import org.mypico.jpico.crypto.Nonce;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Convenience class which provides a custom {@link com.google.gson.Gson} instance for
 * JSON-serializing the various {@link org.mypico.jpico.crypto.messages} classes.
 *
 * @author Max Spencer &lt;ms955@cl.cam.ac.uk&gt;
 */
public class MessageGson {

    /**
     * The custom <code>Gson</code> instance.
     */
    public static final Gson gson = new GsonBuilder()
        .registerTypeAdapter(byte[].class, new ByteArrayGsonSerializer())
        .registerTypeAdapter(PublicKey.class, new PublicKeyGsonSerializer())
        .registerTypeAdapter(Nonce.class, new NonceGsonSerializer())
        .disableHtmlEscaping()
        .create();
}
