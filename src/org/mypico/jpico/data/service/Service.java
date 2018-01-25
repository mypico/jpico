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


package org.mypico.jpico.data.service;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.net.URI;

import org.mypico.jpico.data.Saveable;

/**
 * A service which the Pico can authenticate to. All <code>Service</code> instances have an ID, a
 * human-readable name and a URI. The URI is for the server the Pico should contact to authenticate
 * to the service. Services the Pico wishes carry out the key-based authentication protocol with
 * must have a non-null public key.
 * <p>
 * <p>
 * This class is part of a <a href="http://en.wikipedia.org/wiki/Bridge_pattern">Bridge pattern</a>.
 * Each <code>Service</code> instance has a reference to a concrete {@link ServiceImp} instance. See
 * {@link org.mypico.jpico.test.data.service} package documentation for more information on this
 * pattern. Specifically, a <code>Service</code> instance forwards the following methods to its
 * <code>ServiceImp</code>:
 * <ul>
 * <li>{@link #save()}
 * <li>{@link #getId()}
 * <li>{@link #getName()}
 * <li>{@link #getAddress()}
 * <li>{@link #getCommitment()}
 * </ul>
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see ServiceImp
 * @see ServiceImpFactory
 * @see ServiceAccessor
 */
public class Service implements Saveable {

    private final ServiceImp imp;

    /**
     * Construct a <code>Service</code> instance using an existing <code>ServiceImp</code>.
     *
     * @param imp existing <code>ServiceImp</code>.
     * @throws NullPointerException if <code>imp</code> is <code>null</code>.
     */
    public Service(final ServiceImp imp) {
        this.imp = checkNotNull(imp);
    }

    /**
     * Construct a new <code>Service</code> instance.
     *
     * @param factory    factory to use to create the new <code>ServiceImp</code>.
     * @param name       human-readable name of the new service.
     * @param address    address of the server of the new service.
     * @param commitment commitment of the new service.
     * @throws NullPointerException     if any argument is <code>null</code>.
     * @throws IllegalArgumentException if <code>name</code> or <code>commitment</code> is the empty
     *                                  string.
     */
    public Service(
        final ServiceImpFactory factory,
        final String name,
        final URI address,
        final byte[] commitment) {
        // Check arguments:
        checkNotNull(factory);
        Service.checkName(name);
        checkNotNull(address);
        Service.checkCommitment(commitment);

        imp = factory.getImp(name, address, commitment);
    }

    /**
     * Copy-constructor. Uses <code>factory</code> to create a new underlying
     * <code>ServiceImp</code> from <code>service</code>.
     *
     * @param factory factory to use to create the new <code>ServiceImp</code>.
     * @param service instance to copy.
     */
    public Service(final ServiceImpFactory factory, final Service service) {
        // Check arguments:
        checkNotNull(factory);
        checkNotNull(service);

        imp = factory.getImp(service);
    }

    /**
     * @return the <code>ServiceImp</code> of this <code>Service</code>.
     */
    public ServiceImp getImp() {
        return imp;
    }

    @Override
    public String toString() {
        return String.format("<Service %d: \"%s\">", getId(), getName());
    }

    /**
     * Test for equality between <code>Service</code> instances.
     *
     * @return <code>true</code> if the IDs of the <code>Service</code> instances are equal or
     * <code>false</code> otherwise.
     * @throws IllegalStateException if both <code>Service</code> instances are unsaved (see
     *                               {@link Saveable#isSaved()}).
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof Service) {
            final Service other = (Service) obj;
            if (isSaved() || other.isSaved()) {
                return (getId() == other.getId());
            } else {
                throw new IllegalStateException(
                    "Cannot compare two unsaved Service instances.");
            }
        } else {
            return false;
        }
    }

    /**
     * @return the ID of this <code>Service</code> instance.
     */
    @Override
    public int hashCode() {
        return getId();
    }

    @Override
    public void save() throws IOException {
        imp.save();
    }

    @Override
    public boolean isSaved() {
        return imp.isSaved();
    }

    // Getters and setters

    /**
     * @return the ID of this service.
     */
    public int getId() {
        return imp.getId();
    }

    /**
     * @return the human-readable name of this service.
     */
    public String getName() {
        return imp.getName();
    }

    /**
     * Set the address of the service's authentication server.
     *
     * @param address new address.
     */
    public void setAddress(final URI address) {
        imp.setAddress(checkNotNull(address));
    }

    /**
     * @return the address of the service's authentication server.
     */
    public URI getAddress() {
        return imp.getAddress();
    }

    /**
     * @return the commitment of this service.
     */
    public byte[] getCommitment() {
        return imp.getCommitment();
    }

    // Argument checks:

    /**
     * Check a potential service name. Service names cannot be <code>null</code> or the empty
     * string.
     *
     * @param name potential service name.
     * @return the potential service name.
     * @throws NullPointerException     if <code>name</code> is <code>null</code>.
     * @throws IllegalArgumentException if <code>name</code> is the empty string.
     */
    public static String checkName(final String name) {
        checkNotNull(name);
        checkArgument(!name.equals(""), "Service name cannot be empty string");
        return name;
    }

    /**
     * Check a potential service commitment. Service commitments cannot be <code>null</code> or the
     * empty string.
     *
     * @param commitment potential service commitment.
     * @return the potential service commitment.
     * @throws NullPointerException     if <code>name</code> is <code>null</code>.
     * @throws IllegalArgumentException if <code>name</code> is the empty string.
     */
    public static byte[] checkCommitment(final byte[] commitment) {
        checkNotNull(commitment);
        checkArgument(
            commitment.length > 0,
            "Service commitment cannot be zero-length");
        return commitment;
    }
}
