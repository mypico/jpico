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


package org.mypico.jpico;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.net.URI;

/**
 * Provides utility methods for checking preconditions to methods and other blocks of code.
 * The checks can be used to ensure data items and parameters are not null and contain data (are
 * not empty).
 */
public class Preconditions {

    /**
     * Check that a byte array is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param b The byte array to check.
     * @return true if it's not null and not empty; false o/w.
     */
    public static byte[] checkNotNullOrEmpty(byte[] b) {
        checkNotNull(b);
        checkArgument(b.length > 0);
        return b;
    }

    /**
     * Check that a byte array is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param b            The byte array to check.
     * @param errorMessage The message to report back in the exception.
     * @return true if it's not null and not empty; false o/w.
     */
    public static byte[] checkNotNullOrEmpty(byte[] b, String errorMessage) {
        checkNotNull(b, errorMessage);
        checkArgument(b.length > 0, errorMessage);
        return b;
    }

    /**
     * Check that a byte array is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param b                    The byte array to check.
     * @param errorMessageTemplate Error message template.
     * @param errorMessageArgs     Arguments to fill out the error message template with.
     * @return true if it's not null and not empty; false o/w.
     */
    public static byte[] checkNotNullOrEmpty(
        byte[] b,
        String errorMessageTemplate,
        Object... errorMessageArgs) {
        checkNotNull(b, errorMessageTemplate, errorMessageArgs);
        checkArgument(b.length > 0, errorMessageTemplate, errorMessageArgs);
        return b;
    }

    /**
     * Check that a URI is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param uri The URI to check.
     * @return true if it's not null and not empty; false o/w.
     */
    public static URI checkNotNullOrEmpty(URI uri) {
        checkNotNull(uri);
        checkArgument(uri.toString().length() > 0);
        return uri;
    }

    /**
     * Check that a URI is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param uri          The URI to check.
     * @param errorMessage The message to report back in the exception.
     * @return true if it's not null and not empty; false o/w.
     */
    public static URI checkNotNullOrEmpty(URI uri, String errorMessage) {
        checkNotNull(uri, errorMessage);
        checkArgument(uri.toString().length() > 0, errorMessage);
        return uri;
    }

    /**
     * Check that a URI is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param uri                  The URI to check.
     * @param errorMessageTemplate Error message template.
     * @param errorMessageArgs     Arguments to fill out the error message template with.
     * @return true if it's not null and not empty; false o/w.
     */
    public static URI checkNotNullOrEmpty(
        URI uri,
        String errorMessageTemplate,
        Object... errorMessageArgs) {
        checkNotNull(uri, errorMessageTemplate, errorMessageArgs);
        checkArgument(uri.toString().length() > 0, errorMessageTemplate, errorMessageArgs);
        return uri;
    }

    /**
     * Check that a string is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param s The string to check.
     * @return true if it's not null and not empty; false o/w.
     */
    public static String checkNotNullOrEmpty(String s) {
        checkNotNull(s);
        checkArgument(s.length() > 0);
        return s;
    }

    /**
     * Check that a string is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param s            The string to check.
     * @param errorMessage The message to report back in the exception.
     * @return true if it's not null and not empty; false o/w.
     */
    public static String checkNotNullOrEmpty(String s, String errorMessage) {
        checkNotNull(s, errorMessage);
        checkArgument(s.length() > 0, errorMessage);
        return s;
    }

    /**
     * Check that a string is not null and has length greater than zero. If either of these
     * are the case, throw a exception.
     *
     * @param s                    The string to check.
     * @param errorMessageTemplate Error message template.
     * @param errorMessageArgs     Arguments to fill out the error message template with.
     * @return true if it's not null and not empty; false o/w.
     */
    public static String checkNotNullOrEmpty(
        String s,
        String errorMessageTemplate,
        Object... errorMessageArgs) {
        checkNotNull(s, errorMessageTemplate, errorMessageArgs);
        checkArgument(s.length() > 0, errorMessageTemplate, errorMessageArgs);
        return s;
    }
}
