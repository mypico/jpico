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


package org.mypico.jpico.data;

import org.mypico.jpico.data.pairing.KeyPairingAccessor;
import org.mypico.jpico.data.pairing.LensPairingAccessor;
import org.mypico.jpico.data.pairing.PairingAccessor;
import org.mypico.jpico.data.service.ServiceAccessor;
import org.mypico.jpico.data.session.SessionAccessor;
import org.mypico.jpico.data.terminal.Terminal;

/**
 * Interface that should be implemented for classes accessing data stored in the database.
 */
public interface DataAccessor
    extends LensPairingAccessor, KeyPairingAccessor,
    PairingAccessor, ServiceAccessor, SessionAccessor, Terminal.Accessor {

}
