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

import org.mypico.jpico.data.pairing.KeyPairingImpFactory;
import org.mypico.jpico.data.pairing.LensPairingImpFactory;
import org.mypico.jpico.data.pairing.PairingImpFactory;
import org.mypico.jpico.data.service.ServiceImpFactory;
import org.mypico.jpico.data.session.SessionImpFactory;
import org.mypico.jpico.data.terminal.Terminal;

/**
 * Interface that should be implemented for factory classes that create concrete instances of the
 * objects stored in the database.
 */
public interface DataFactory extends
    ServiceImpFactory,
    PairingImpFactory,
    KeyPairingImpFactory,
    LensPairingImpFactory,
    SessionImpFactory,
    Terminal.ImpFactory {

}
