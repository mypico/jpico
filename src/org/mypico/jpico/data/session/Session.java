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


package org.mypico.jpico.data.session;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.util.Date;

import javax.crypto.SecretKey;

import org.mypico.jpico.crypto.AuthToken;
import org.mypico.jpico.data.Saveable;
import org.mypico.jpico.data.pairing.Pairing;

/**
 * An authentication session between the Pico and a service. A Pico "uses" a particular pairing each
 * time it authenticates and starts a new authentication session. A session always has a local ID an
 * associated {@link Pairing} instance is used when attempting to authenticate and a current state
 * (see {@link Session.Status}).
 *
 * @author Chris Warrington <cw471@cam.ac.uk>
 * @author David Llewellyn-Jones <dl551@cam.ac.uk>
 * @author Graeme Jenkinson <gcj21@cam.ac.uk>
 * @author Max Spencer <ms955@cam.ac.uk>
 * @see SessionImp
 * @see SessionImpFactory
 */
public class Session implements Saveable {

    /**
     * Statuses a session can have.
     */
    public enum Status {
        ACTIVE,
        PAUSED,
        CLOSED,
        ERROR
    }

    /**
     * Specific errors a session can have when its status is {@link Session.Status#ERROR}.
     */
    public enum Error {
        NONE,
        IO_EXCEPTION,
        SERVICE_AUTHENTICATION_FAILURE,
        SERVICE_REPORTED_ERROR
    }

    private final SessionImp imp;

    /**
     * Construct a <code>Session</code> instance using an existing <code>SessionImp</code>.
     *
     * @param imp existing <code>SessionImp</code>.
     */
    public Session(final SessionImp imp) {
        this.imp = checkNotNull(imp);
    }

    /**
     * Copy-constructor. Uses <code>factory</code> to create a new underlying
     * <code>SessionImp</code> from <code>session</code>.
     *
     * @param factory factory to use to create the new <code>SessionImp</code>.
     * @param session instance to copy.
     */
    public Session(final SessionImpFactory factory, final Session session) {
        // Check arguments:
        checkNotNull(factory);
        checkNotNull(session);

        imp = factory.getImp(session);
    }

    /**
     * Create a new <code>Session</code> instance in the {@link Session.Status#ACTIVE} state.
     *
     * @param factory   factory to use to create the new <code>SessionImp</code>.
     * @param remoteId  remote ID of the new session.
     * @param secretKey symmetric secret key of the new session.
     * @param pairing   pairing of the new session.
     * @param authToken authorisation token of the new session.
     * @return The newly created active <code>Session</code>.
     * @throws NullPointerException if any argument is <code>null</code>.
     */
    public static Session newInstanceActive(
        final SessionImpFactory factory,
        final String remoteId,
        final SecretKey secretKey,
        final Pairing pairing,
        final AuthToken authToken) {

        // Verify the method's preconditions
        checkNotNull(factory, "SessionImpFactory can't be null");
        checkNotNull(remoteId, "remoteId can't be null");
        checkNotNull(secretKey, "SecretKey can't be null");
        checkNotNull(pairing, "Pairing can't be null");

        return new Session(
            factory.getImp(
                remoteId,
                secretKey,
                pairing,
                authToken,
                new Date(), // now
                Status.ACTIVE,
                Error.NONE));
    }

    /**
     * Create a new <code>Session</code> instance in the <code>Paused</code> state.
     *
     * @param factory   factory to use to create the new <code>SessionImp</code>.
     * @param remoteId  remote ID of the new session.
     * @param secretKey symmetric secret key of the new session.
     * @param pairing   pairing of the new session.
     * @param authToken authorisation token of the new session.
     * @return The newly created paused <code>Session</code>.
     */
    public static Session newInstancePaused(
        final SessionImpFactory factory,
        final String remoteId,
        final SecretKey secretKey,
        final Pairing pairing,
        final AuthToken authToken) {

        // Verify the method's preconditions
        checkNotNull(factory, "SessionImpFactory can't be null");
        checkNotNull(remoteId, "remoteId can't be null");
        checkNotNull(secretKey, "SecretKey can't be null");
        checkNotNull(pairing, "Pairing can't be null");

        return new Session(
            factory.getImp(
                remoteId,
                secretKey,
                pairing,
                authToken,
                new Date(), // now
                Status.PAUSED,
                Error.NONE));
    }

    /**
     * Create a new <code>Session</code> instance in the <code>CLOSED</code> state.
     *
     * @param factory   factory to use to create the new <code>SessionImp</code>.
     * @param remoteId  remote ID of the new session.
     * @param pairing   pairing of the new session.
     * @param authToken authorisation token of the new session.
     * @return The newly created closed <code>Session</code>.
     */
    public static Session newInstanceClosed(
        final SessionImpFactory factory,
        final String remoteId,
        final Pairing pairing,
        final AuthToken authToken) {

        // Verify the method's preconditions
        checkNotNull(factory, "SessionImpFactory can't be null");
        checkNotNull(pairing, "Pairing can't be null");

        return new Session(
            factory.getImp(
                remoteId,
                null,
                pairing,
                authToken,
                new Date(), // now
                Status.CLOSED,
                Error.NONE));
    }

    /**
     * Create a new <code>Session</code> instance in the <code>ERROR</code> state.
     *
     * @param factory factory to use to create the new <code>SessionImp</code>.
     * @param pairing pairing of the new session.
     * @param error   specific error of the new session.
     * @return The newly created error <code>Session</code>.
     */
    public static Session newInstanceInError(
        final SessionImpFactory factory,
        final Pairing pairing,
        final Error error) {

        // Verify the method's preconditions
        checkNotNull(
            factory, "SessionImpFactory can't be null");
        checkNotNull(
            pairing, "Pairing can't be null");
        checkNotNull(
            error, "Error can't be null");

        return new Session(
            factory.getImp(
                null,
                null,
                pairing,
                null,
                new Date(), // now
                Status.ERROR,
                error));
    }

    /**
     * @return the <code>SessionImp</code> of this <code>Session</code>.
     */
    public SessionImp getImp() {
        return imp;
    }

    @Override
    public String toString() {
        return String.format("<Session %d: for %s>",
            getId(),
            getPairing());
    }

    /**
     * Test for equality between <code>Session</code> instances.
     *
     * @return <code>true</code> if the IDs of the <code>Session</code> instances are equal or
     * <code>false</code> otherwise.
     * @throws IllegalStateException if both <code>Session</code> instances are unsaved (see
     *                               {@link Saveable#isSaved()}).
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Session) {
            Session other = (Session) obj;
            if (isSaved() || other.isSaved()) {
                return (getId() == other.getId());
            } else {
                throw new IllegalStateException(
                    "Cannot compare two unsaved Session instances.");
            }
        } else {
            return false;
        }
    }

    /**
     * @return the ID of this <code>Session</code> instance.
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
     * @return the local ID of this session.
     */
    public int getId() {
        return imp.getId();
    }

    /**
     * @return the remote ID of this session that identifies it to the service.
     */
    public String getRemoteId() {
        return imp.getRemoteId();
    }

    /**
     * @return the symmetric shared secret of this session.
     */
    public SecretKey getSecretKey() {
        return imp.getSecretKey();
    }

    /**
     * @return the pairing of this session.
     */
    public Pairing getPairing() {
        return imp.getPairing();
    }

    /**
     * @return the current status of this session.
     */
    public Status getStatus() {
        return imp.getStatus();
    }

    /**
     * Set the current status of this session.
     *
     * @param status new status.
     * @throws NullPointerException if <code>status</code> is <code>null</code>.
     */
    public void setStatus(final Status status) {
        imp.setStatus(checkNotNull(status));
    }

    /**
     * @return the specific current error of this session.
     */
    public Error getError() {
        return imp.getError();
    }

    /**
     * Set the current specific error of this session.
     *
     * @param error new error.
     * @throws NullPointerException if <code>error</code> is <code>null</code>.
     */
    public void setError(final Error error) {
        imp.setError(checkNotNull(error));
    }

    /**
     * @return the date when this session was last authenticated.
     */
    public Date getLastAuthDate() {
        return imp.getLastAuthDate();
    }

    /**
     * Set the last authentication date of this session.
     *
     * @param lastAuthDate last authentication date.
     * @throws NullPointerException     if <code>lastAuthDate</code> is <code>null</code>.
     * @throws IllegalArgumentException if <code>lastAuthDate</code> is in the future.
     */
    public void setLastAuthDate(final Date lastAuthDate) {
        imp.setLastAuthDate(Session.checkLastAuthDate(lastAuthDate));
    }

    /**
     * Check whether this session has an authorisation token which can be read.
     * <p>
     * <p>
     * This method and {@link #getAuthToken()} are not thread safe.
     *
     * @return <code>true</code> if this session has an authorisation token which can be read.
     */
    public boolean hasAuthToken() {
        return imp.hasAuthToken();
    }

    /**
     * Return this session's authorisation token.
     * <p>
     * <p>
     * This method and {@link #getAuthToken() getAuthToken} are not thread safe.
     *
     * @return the authorisation token of this session.
     */
    public AuthToken getAuthToken() {
        return imp.getAuthToken();
    }

    // Argument checks:

    /**
     * Check a potential session remote ID. Session remote IDs cannot be <code>null</code> or the
     * empty string.
     *
     * @param remoteId potential remote ID.
     * @return the potential remote ID.
     * @throws NullPointerException     if <code>remoteID</code> is <code>null</code>.
     * @throws IllegalArgumentException if <code>remoteID</code> is the empty string.
     */
    public static String checkRemoteId(String remoteId) {
        checkNotNull(remoteId);
        checkArgument(
            !remoteId.equals(""),
            "Session remote ID cannot be empty string");
        return remoteId;
    }

    /**
     * Check a potential session last authentication date. Such a date cannot be <code>null</code>
     * and cannot be in the future.
     *
     * @param lastAuthDate potential date.
     * @return the potential date.
     * @throws NullPointerException     if <code>lastAuthDate</code> is <code>null</code>.
     * @throws IllegalArgumentException if <code>lastAuthDate</code> is in the future.
     */
    public static Date checkLastAuthDate(Date lastAuthDate)
        throws NullPointerException, IllegalArgumentException {
        checkNotNull(lastAuthDate, "Session last auth date cannot be null");
        checkArgument(
            lastAuthDate.compareTo(new Date()) <= 0,
            "Session last auth date cannot be in the future");
        return lastAuthDate;
    }
}
