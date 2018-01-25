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


/**
 * Provides the classes and interfaces which describe the API for allowing backups of the Pico
 * database to be created, encrypted, decrypted and restored. The backup process is important
 * for Pico, as it ensures, in the event that a Pico is lost, that all of the accounts stored
 * on the Pico aren't also lost. By using the backup and restore functionality, a temporary Pico
 * can also be configured in case a Pico becomes broken, or is temporarily unavailable.
 *
 * Since the backup stores all data needed to access the user's account, it's important that the
 * backup is encrypted to avoid allowing others access to the accounts.
 *
 * Pico allows the backup to be stored in a variety of places, including locally or on various
 * Cloud services (e.g. DropBox). It's considered safe to store the backup on an external,
 * untrusted, service due to the encryption used.
 *
 * JPico does not handle the process of uploading/downloading the backup to/from a service, it
 * just manages creation or interpretation of the file used for this. The storage part is managed,
 * for example, by the android-pico app.
 *
 */
package org.mypico.jpico.backup;