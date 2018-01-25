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


package org.mypico.jpico.data.pairing;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.mypico.jpico.crypto.HashUtils;
import org.mypico.jpico.data.service.Service;

/**
 * A pairing the Pico can use to authenticate to a Pico-enabled service. Extends {@link Pairing} to
 * include an asymmetric key pair which the Pico can use to carry out the key-based
 * <em>Pico authentication protocol</em>.
 * <p>
 * <p>
 * This class is part of a <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge pattern</a>.
 * Each <code>KeyPairing</code> instance has a reference to a concrete {@link KeyPairingImp}
 * instance. See {@link org.mypico.jpico.test.data.pairing} package documentation for more information
 * on this pattern. Specifically, a <code>KeyPairing</code> instance forwards
 * {@link #getPublicKey()} and {@link #getPrivateKey()} to its <code>KeyPairingImp</code>.
 *
 * @author Claudio Dettoni <cd611@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see KeyPairingImp
 * @see KeyPairingImpFactory
 * @see KeyPairingAccessor
 */
public class KeyPairing extends Pairing {

    private final KeyPairingImp imp;

    /**
     * Construct a new <code>KeyPairing</code> instance using an existing <code>KeyPairingImp</code>
     * .
     *
     * @param imp existing <code>KeyPairingImp</code>.
     * @throws NullPointerException if <code>imp</code> is <code>null</code>.
     */
    public KeyPairing(final KeyPairingImp imp) {
        super(checkNotNull(imp));
        this.imp = imp;
    }

    /**
     * Construct a new <code>KeyPairing</code> instance.
     *
     * @param factory    factory to use to create the new <code>LensPairingImp</code>.
     * @param name       human-readable name of the new pairing.
     * @param service    service of the new pairing.
     * @param publicKey  public key of the new pairing.
     * @param privateKey private key of the new pairing.
     * @param extraData  data requested to store. Usually a password
     * @throws NullPointerException     if any argument is <code>null</code>.
     * @throws IllegalArgumentException if <code>name</code> is the empty string.
     */
    public KeyPairing(
        KeyPairingImpFactory factory,
        String name,
        Service service,
        PublicKey publicKey,
        PrivateKey privateKey,
        String extraData) {
        this(factory.getImp(
            Pairing.checkName(name),
            checkNotNull(service, "KeyPairing service cannot be null"),
            checkNotNull(publicKey, "KeyPairing public key cannot be null"),
            checkNotNull(privateKey, "KeyPairing private key cannot be null"),
            extraData));
    }

    /**
     * Construct a new <code>KeyPairing</code> instance.
     *
     * @param factory   factory to use to create the new <code>LensPairingImp</code>.
     * @param name      human-readable name of the new pairing.
     * @param service   service of the new pairing.
     * @param keyPair   public/private key pair of the new pairing.
     * @param extraData data requested to store. Usually a password
     * @throws NullPointerException     if any argument is <code>null</code>.
     * @throws IllegalArgumentException if <code>name</code> is the empty string.
     */
    public KeyPairing(
        KeyPairingImpFactory factory,
        String name,
        Service service,
        KeyPair keyPair,
        String extraData) {
        this(factory.getImp(
            Pairing.checkName(name),
            checkNotNull(service, "KeyPairing service cannot be null"),
            checkNotNull(keyPair, "KeyPairing cannot be constructed with a null key pair"),
            extraData));
    }

    /**
     * Copy-constructor. Uses <code>factory</code> to create a new underlying
     * <code>KeyPairingImp</code> from <code>keyPairing</code>.
     *
     * @param factory    factory to use to create the new <code>KeyPairingImp</code>.
     * @param keyPairing instance to copy.
     */
    public KeyPairing(KeyPairingImpFactory factory, KeyPairing keyPairing) {
        this(factory.getImp(checkNotNull(keyPairing)));
    }

    @Override
    public String toString() {
        return String.format(
            "<KeyPairing %d: \"%s\" for %s>",
            getId(),
            getName(),
            getService());
    }

    /**
     * @return the public key of this key pairing.
     */
    public PublicKey getPublicKey() {
        return imp.getPublicKey();
    }

    /**
     * @return the private get of this key pairing.
     */
    public PrivateKey getPrivateKey() {
        return imp.getPrivateKey();
    }

    public String getExtraData() {
        return imp.getExtraData();
    }

    /**
     * Create a pre-image resistant commitment of the long-term identity public key of a service.
     *
     * @param servicePublicKey public key of the service.
     * @return pre-image resistant commitment.
     */
    public static byte[] commitServicePublicKey(PublicKey servicePublicKey) {
        return HashUtils.sha256Key(servicePublicKey);
    }
}
