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
 * pairings. A Pico can have pairings with many services and may have more than one pairing for each
 * service. A Pico "uses" a particular pairing each time it authenticates, meaning it presents and
 * authenticates an identity in that pairing, to the service that pairing is "with".
 *
 * <p>
 * Each pairing which can be used to authenticate is either a
 * {@link org.mypico.jpico.data.pairing.KeyPairing} or a
 * {@link org.mypico.jpico.data.pairing.LensPairing}. In the former case, the pairing includes an
 * asymmetric key pair and the Pico will carry out the key-based
 * <em>Pico authentication protocol</em> when it authenticates using that pairing. In the latter
 * case the pairing was created using a Pico Lens browser plugin and the credentials of such a
 * pairing are the traditional username/password credentials of a user's account on a non
 * Pico-compliant web site.
 *
 * <p>
 * <code>KeyPairing</code> and <code>LensPairing</code> are both subclasses of
 * {@link org.mypico.jpico.data.pairing.Pairing}. A plain base class <code>Pairing</code> may
 * exist, but has no credentials of either type and so cannot be used to authenticate.
 *
 * <p>
 * The <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge pattern</a> is used to separate
 * the interface of a <code>Pairing</code>, <code>KeyPairing</code> or <code>LensPairing</code>
 * instance from the underlying {@link org.mypico.jpico.data.Saveable} implementation. This
 * underlying implementation, which is a concrete {@link org.mypico.jpico.data.pairing.PairingImp},
 * {@link org.mypico.jpico.data.pairing.KeyPairingImp} or
 * {@link org.mypico.jpico.data.pairing.LensPairingImp}, may have tight coupling with third-party,
 * platform-dependent libraries in order to implement <code>Saveable</code>. <code>PairingImp</code>, <code>KeyPairingImp</code> and <code>LensPairingImp</code> instances are created by a
 * corresponding type of factory, such as
 * {@link org.mypico.jpico.data.pairing.KeyPairingImpFactory}, which have various
 * <code>getImp</code> methods such as
 * {@link org.mypico.jpico.data.pairing.KeyPairingImpFactory#getImp(KeyPairing)}.
 * <code>Pairing</code>, <code>KeyPairing</code> and <code>LensPairing</code> instances can be
 * retrieved from a permanent data store using a corresponding type of accessor, such as
 * {@link org.mypico.jpico.data.pairing.KeyPairingAccessor}, which have various query methods such
 * as {@link org.mypico.jpico.data.pairing.KeyPairingAccessor#getKeyPairingById(int)}.
 *
 * <h3>Summary of the relationships between the classes in this package</h3>
 *
 * <h4><code>Pairing</code> group</h4>
 * <ul>
 * <li>Each <code>Pairing</code> has a concrete <code>PairingImp</code> instance.
 * <li><code>PairingImp</code> instances are created using a <code>PairingImpFactory</code>.
 * <li><code>Pairing</code> instances are returned by the query methods of a
 * <code>PairingAccessor</code>.
 * </ul>
 *
 * <h4><code>KeyPairing</code> group</h4>
 * <ul>
 * <li>Each <code>KeyPairing</code> has a concrete <code>KeyPairingImp</code> instance.
 * <li><code>KeyPairingImp</code> instances are created using a <code>KeyPairingImpFactory</code>.
 * <li><code>KeyPairing</code> instances are returned by the query methods of a
 * <code>KeyPairingAccessor</code>.
 * </ul>
 *
 * <h4><code>LensPairing</code> group</h4>
 * <ul>
 * <li>Each <code>LensPairing</code> has a concrete <code>LensPairingImp</code> instance.
 * <li><code>LensPairingImp</code> instances are created using a <code>LensPairingImpFactory</code>.
 * <li><code>LensPairing</code> instances are returned by the query methods of a
 * <code>LensPairingAccessor</code>.
 * </ul>
 *
 */
package org.mypico.jpico.data.pairing;