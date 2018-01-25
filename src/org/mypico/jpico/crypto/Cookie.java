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


package org.mypico.jpico.crypto;

import java.text.SimpleDateFormat;
import java.util.Date;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.base.Objects;
import com.google.common.base.Strings;
import com.google.gson.annotations.SerializedName;

/**
 * A class representing a browser cookie, containing the cookie contents and a validity date.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 */
public class Cookie {

    private final static String RFC1123_DATE_PATTERN =
        "EEE, dd MMM yyyy HH:mm:ss zzz";
    private final static SimpleDateFormat dateFormat =
        new SimpleDateFormat(RFC1123_DATE_PATTERN);

    @SerializedName("url")
    public final String url;
    @SerializedName("value")
    public final String value;
    @SerializedName("date")
    public final String date;

    /**
     * Constructor.
     *
     * @param url   The site the cookie belongs to.
     * @param value The contents of the cookie.
     * @param date  The time/date the cookie is valid until.
     */
    public Cookie(final String url, final String value, final String date) {
        // Verify the method's preconditions        
        this.url = checkNotNull(url, "Cookie URL cannot be null");
        ;
        this.value = checkNotNull(value, "Cookie value cannot be null");
        ;
        if (Strings.isNullOrEmpty(date)) {
            this.date = "Date: " + dateFormat.format(new Date());
        } else {
            this.date = date;
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (!(o instanceof Cookie))
            return false;
        final Cookie cookie = (Cookie) o;
        return (url.equals(cookie.url) && value.equals(cookie.value) && date.equals(cookie.date));
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(url, value, date);
    }

    public String getNameValue() {
        if (value.indexOf(";") > 0) {
            return value.substring(0, value.indexOf(";"));
        } else {
            return value;
        }
    }

    @Override
    public String toString() {
        return String.format("Url:%s Value:%s Date:%s",
            url, value, date);
    }
}