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


package org.mypico.jpico.data.terminal;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import org.mypico.jpico.Preconditions;
import org.mypico.jpico.data.Saveable;

/**
 * A terminal is a device or piece of software that you use to access another remote service. When
 * Pico authenticates to a service accessed this way, Pico will authenticate directly with the
 * service, but must then interact with the termainal, in order to delegate access to the
 * terminal.
 * <p>
 * This class captures the details needed for Pico to interact with a terminal for this purpose.
 *
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see org.mypico.jpico.db.DbTerminalImp
 */
public class Terminal implements Saveable {

    public interface Imp extends Saveable {
        public int getId();

        public String getName();

        public byte[] getCommitment();

        public PublicKey getPicoPublicKey();

        public PrivateKey getPicoPrivateKey();

        public void delete() throws IOException;
    }

    public interface ImpFactory {
        Imp getImp(
            String name,
            byte[] commitment,
            PublicKey picoPublicKey,
            PrivateKey picoPrivateKey);

        Imp getImp(Terminal terminal);
    }

    public interface Accessor {
        /**
         * Query the store for a terminal with a given ID.
         *
         * @param id ID to query for.
         * @return <code>Terminal</code> instance with matching ID or <code>null</code> if none could be
         * found in the data store.
         * @throws IOException if an <code>IOException</code> occurred whilst querying the data store.
         */
        public Terminal getTerminalById(int id) throws IOException;

        /**
         * Query the store for a terminal with a given commitment.
         *
         * @param commitment commitment to query for.
         * @return <code>Terminal</code> instance with matching commitment or <code>null</code> if none
         * could be found in the data store.
         * @throws IOException if an <code>IOException</code> occurred whilst querying the data store.
         */
        public Terminal getTerminalByCommitment(byte[] commitment)
            throws IOException;

        /**
         * Query the store for all terminals.
         *
         * @return a list containing all terminals in the data store.
         * @throws IOException is an <code>IOException</code> occurred whilst querying the data
         *                     store.
         */
        public List<Terminal> getAllTerminals() throws IOException;
    }

    private final Imp imp;

    /**
     * Construct a <code>Terminal</code> instance using an existing
     * <code>TerminalImp</code>.
     *
     * @param imp existing <code>TerminalImp</code>.
     * @throws NullPointerException if <code>imp</code> is <code>null</code>.
     */
    public Terminal(final Imp imp) {
        this.imp = checkNotNull(imp, "imp cannot be null");
    }

    public Terminal(
        final ImpFactory factory,
        final String name,
        final byte[] commitment,
        final PublicKey picoPublicKey,
        final PrivateKey picoPrivateKey) {
        this(factory.getImp(
            Preconditions.checkNotNullOrEmpty(name, "name cannot be null or empty"),
            Preconditions.checkNotNullOrEmpty(commitment, "commitment cannot be null or empty"),
            checkNotNull(picoPublicKey, "picoPublicKey cannot be null"),
            checkNotNull(picoPrivateKey, "picoPrivateKey cannot be null")));
    }

    /**
     * Construct a <code>Terminal</code> instance using the details provided.
     *
     * @param factory     Factory for creating concrete <code>Terminal</code> instances.
     * @param name        Name of the terminal.
     * @param commitment  The terminal commitment.
     * @param picoKeyPair The long term idenity key pair the Pico uses to authenticate to the
     *                    terminal.
     */
    public Terminal(
        final ImpFactory factory,
        final String name,
        final byte[] commitment,
        final KeyPair picoKeyPair) {
        this(
            factory,
            name,
            commitment,
            checkNotNull(picoKeyPair, "picoKeyPair cannot be null").getPublic(),
            picoKeyPair.getPrivate());
    }

    @Override
    public String toString() {
        return String.format("<Terminal %d: \"%s\">", getId(), getName());
    }

    /**
     * Test for equality between <code>Terminal</code> instances.
     *
     * @return <code>true</code> if the IDs of the <code>Terminal</code> instances are equal or
     * <code>false</code> otherwise.
     * @throws IllegalStateException if both <code>Terminal</code> instances are unsaved (see
     *                               {@link Saveable#isSaved()}).
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof Terminal) {
            final Terminal other = (Terminal) obj;
            if (isSaved() || other.isSaved()) {
                return (getId() == other.getId());
            } else {
                throw new IllegalStateException(
                    "Cannot compare two unsaved Terminal instances.");
            }
        } else {
            return false;
        }
    }

    /**
     * Get the ID of the terminal.
     *
     * @return the ID of this <code>Terminal</code> instance.
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

    public void delete() throws IOException {
        imp.delete();
    }

    /**
     * Get the id of the terminal.
     *
     * @return the ID of this terminal.
     */
    public int getId() {
        return imp.getId();
    }

    /**
     * Get a human-readable name for the terminal.
     *
     * @return the human-readable name for this terminal.
     */
    public String getName() {
        return imp.getName();
    }

    /**
     * Get the terminal commitment.
     *
     * @return the commitment of this terminal.
     */
    public byte[] getCommitment() {
        return imp.getCommitment();
    }

    /**
     * Get the long term public key the Pico uses to authenticate to the terminal.
     *
     * @return the public key the Pico uses when authenticating to this terminal.
     */
    public PublicKey getPicoPublicKey() {
        return imp.getPicoPublicKey();
    }

    /**
     * Get the private key the Pico uses when authenticating to this terminal.
     *
     * @return the private key the Pico uses when authenticating to this terminal.
     */
    public PrivateKey getPicoPrivateKey() {
        return imp.getPicoPrivateKey();
    }
}
