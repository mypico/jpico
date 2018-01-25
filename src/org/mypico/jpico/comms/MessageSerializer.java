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

/**
 * Interfaces for classes which define a way of serializing and deserializing the various
 * {@link Message} classes.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 */
public interface MessageSerializer {

    /**
     * Serialize a message of a given type to a byte array.
     *
     * @param msg  the message to be serialized.
     * @param type the type of the message.
     * @return a byte array containing the message in some well-defined format.
     * @throws UnsupportedEncodingException if the message can't be encoded.
     */
    public byte[] serialize(Message msg, Type type)
        throws UnsupportedEncodingException;

    /**
     * Deserialize a message of a given type from a byte array.
     *
     * @param bytes    a byte array containing the message in a some well-defined format.
     * @param classOfT the type of the message to be deserialized.
     * @param <T>      the type of the message to be deserialized.
     * @return the deserialized message object.
     * @throws UnsupportedEncodingException if the message can't be decoded.
     */
    public <T extends Message> T deserialize(byte[] bytes, Class<T> classOfT)
        throws UnsupportedEncodingException;
}
