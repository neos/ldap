<?php
namespace Neos\Ldap\Service\BindProvider;

/*                                                                        *
 * This script belongs to the Flow package "Neos.Ldap".                  *
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
 * The Neos project - inspiring people to share!                         *
 *                                                                        */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Error\Exception;

/**
 * Bind to an ActiveDirectory Server
 *
 * @Flow\Scope("prototype")
 */
class ActiveDirectoryBind extends AbstractBindProvider
{

    /**
     * Bind to an ActiveDirectory server
     *
     * Prefix the username with a domain if configured.
     *
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function bind($username, $password)
    {
        try {
            ldap_bind($this->linkIdentifier, $this->getUsername($username), $password);
        } catch (\Exception $exception) {
            throw new Exception('Could not bind to ActiveDirectory server. Error was: ' . $exception->getMessage(), 1327937215);
        }
    }

    /**
     * @param string $username
     * @return string
     */
    protected function getUsername($username)
    {
        if (!empty($this->options['domain'])) {
            if (!strpos($username, '\\')) {
                $username = $this->options['domain'] . '\\' . $username;
            }
        }
        if (!empty($this->options['usernameSuffix'])) {
            if (!strpos($username, '@')) {
                $username = $username . '@' . $this->options['usernameSuffix'];
            }
        }
        return $username;
    }

    /**
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function verifyCredentials($username, $password)
    {
        try {
            ldap_bind($this->linkIdentifier, $this->getUsername($username), $password);
        } catch (\Exception $exception) {
            throw new Exception('Could not verify credentials for dn: "' . $username . '"', 1327763970);
        }
    }

    /**
     * Return username in format used for directory search
     *
     * @param string $username
     * @return string
     */
    public function getFilteredUsername($username)
    {
        if (!empty($this->options['domain'])) {
            $usernameParts = explode('\\', $username);
            $usernameWithoutDomain = array_pop($usernameParts);
            return $this->options['filter']['ignoreDomain'] ? $usernameWithoutDomain : addcslashes($username, '\\');
        }
        return $username;
    }

}

