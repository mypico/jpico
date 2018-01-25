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
 * services. A Pico can have pairings with many services and may have more than one pairing for each
 * service.
 *
 * <p>
 * The <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge pattern</a> is used to separate
 * the interface of a {@link org.mypico.jpico.data.service.Service} instance from the underlying
 * {@link org.mypico.jpico.data.Saveable} implementation which is a concrete
 * {@link org.mypico.jpico.data.service.ServiceImp} instance. A concrete <code>ServiceImp</code>
 * may have tight coupling with third-party, platform-dependent libraries in order to implement
 * <code>Saveable</code>. <code>ServiceImp</code> instances are created by a
 * {@link org.mypico.jpico.data.service.ServiceImpFactory}, which has various <code>getImp</code>
 * methods such as {@link org.mypico.jpico.data.service.ServiceImpFactory#getImp(Service)}.
 * <code>Service</code> instances can be retrieved from a permanent data store using a
 * {@link org.mypico.jpico.data.service.ServiceAccessor} which has query methods such as
 * {@link org.mypico.jpico.data.service.ServiceAccessor#getServiceById(int)}.
 *
 * <h3>Summary of the relationships between the classes in this package</h3>
 *
 * <ul>
 * <li>Each <code>Service</code> has a concrete <code>ServiceImp</code> instance.
 * <li><code>ServiceImp</code> instances are created using a <code>ServiceImpFactory</code>.
 * <li><code>Service</code> instances are returned by the query methods of a
 * <code>ServiceAccessor</code>.
 * </ul>
 */
package org.mypico.jpico.data.service;