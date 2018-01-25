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
 * Provides the classes and interfaces which describe the API for the data a Pico stores about
 * services, pairings and sessions. A Pico can have pairings with many services and may have more
 * than one pairing for each service. A Pico "uses" a particular pairing each time it authenticates
 * and starts a new authentication session.
 *
 * @see org.mypico.jpico.test.data.service
 * @see org.mypico.jpico.test.data.pairing
 * @see org.mypico.jpico.test.data.session
 *
 */
package org.mypico.jpico.data;