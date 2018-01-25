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
 * Provides the classes and interfaces for performing the crytographic operations needed by Pico.
 * This includes both the low level management of data structures such as nonces, and the higher
 * level protocol crypto such as running the SIGMA-I prover and verifier protocols.
 *
 * @see org.mypico.jpico.crypto.messages
 * @see org.mypico.jpico.crypto.util
 */
package org.mypico.jpico.crypto;