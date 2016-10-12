<?php
namespace TYPO3\LDAP\Service\BindProvider;

/*                                                                        *
 * This script belongs to the Flow package "TYPO3.LDAP".                  *
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU Lesser General Public License as published by the *
 * Free Software Foundation, either version 3 of the License, or (at your *
 * option) any later version.                                             *
 *                                                                        *
 * This script is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN-    *
 * TABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser       *
 * General Public License for more details.                               *
 *                                                                        *
 * You should have received a copy of the GNU Lesser General Public       *
 * License along with the script.                                         *
 * If not, see http://www.gnu.org/licenses/lgpl.html                      *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

/**
 * Interface for binding.
 */
interface BindProviderInterface
{

    /**
     * The link identifier to connect to the LDAP server
     *
     * @return resource
     */
    public function getLinkIdentifier();

    /**
     * Bind to the server as defined by the settings
     *
     * @param $username
     * @param $password
     */
    public function bind($username, $password);

    /**
     * Bind by dn and password
     *
     * @param $dn
     * @param $password
     */
    public function verifyCredentials($dn, $password);

    /**
     * Get a filtered username
     *
     * @param $username
     */
    public function getFilteredUsername($username);
}

