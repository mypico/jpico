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
 * sessions. A Pico "uses" a particular pairing each time it authenticates and starts a new
 * authentication session.
 *
 * <p>
 * The <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge pattern</a> is used to separate
 * the interface of a {@link org.mypico.jpico.data.session.Session} instance from the underlying
 * {@link org.mypico.jpico.data.Saveable} implementation which is a concrete
 * {@link org.mypico.jpico.data.session.SessionImp} instance. A concrete <code>SessionImp</code>
 * may have tight coupling with third-party, platform-dependent libraries in order to implement
 * <code>Saveable</code>. <code>SessionImp</code> instances are created by a
 * {@link org.mypico.jpico.data.session.SessionImpFactory}, which has various <code>getImp</code>
 * methods such as {@link org.mypico.jpico.data.session.SessionImpFactory#getImp(Session)}.
 *
 * <h3>Summary of the relationships between the classes in this package</h3>
 *
 * <ul>
 * <li>Each <code>Session</code> has a concrete <code>SessionImp</code> instance.
 * <li><code>SessionImp</code> instances are created using a <code>SessionImpFactory</code>.
 * </ul>
 */
package org.mypico.jpico.data.session;