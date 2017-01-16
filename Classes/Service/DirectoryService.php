<?php
namespace Neos\Ldap\Service;

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
use Neos\Utility\Arrays;
use Neos\Ldap\Service\BindProvider\BindProviderInterface;
use Neos\Ldap\Utility\ServerStatusUtility;

/**
 * A simple LDAP authentication service
 * @Flow\Scope("prototype")
 */
class DirectoryService
{

    /**
     * @var string
     */
    protected $name;

    /**
     * @var array
     */
    protected $options;

    /**
     * @var \Neos\Ldap\Service\BindProvider\BindProviderInterface
     */
    protected $bindProvider;

    /**
     * @param string $name
     * @param array $options
     * @throws Exception
     */
    public function __construct($name, array $options)
    {
        $this->name = $name;
        $this->options = $options;

        if (!extension_loaded('ldap')) {
            throw new Exception('PHP is not compiled with LDAP support', 1305406047);
        }
    }

    /**
     * Initialize the LDAP server connection
     *
     * Connect to the server and set communication options. Further bindings will be done
     * by a server specific bind provider.
     *
     * @throws Exception
     */
    public function ldapConnect()
    {
        if ($this->bindProvider instanceof BindProviderInterface) {
            // Already connected
            return;
        }

        $bindProviderClassName = 'Neos\Ldap\Service\BindProvider\\' . $this->options['type'] . 'Bind';
        if (!class_exists($bindProviderClassName)) {
            throw new Exception('An bind provider for the service "' . $this->options['type'] . '" could not be resolved. Make sure it is a valid bind provider name!', 1327756744);
        }

        try {
            $connection = ldap_connect($this->options['host'], $this->options['port']);
            $this->bindProvider = new $bindProviderClassName($connection, $this->options);
            $this->setLdapOptions();
        } catch (\Exception $exception) {
            throw new Exception('Could not connect to LDAP server', 1326985286);
        }
    }

    /**
     * Set the LDAP options configured in the settings
     *
     * Loops over the ldapOptions array, and finds the corresponding LDAP option by prefixing
     * LDAP_OPT_ to the uppercased array key.
     *
     * Example:
     *  protocol_version: 3
     * Becomes:
     *  LDAP_OPT_PROTOCOL_VERSION 3
     *
     * @return void
     */
    protected function setLdapOptions()
    {
        if (!empty($this->options['ldapOptions']) && is_array($this->options['ldapOptions'])) {
            foreach ($this->options['ldapOptions'] as $ldapOption => $ldapOptionValue) {
                $constantName = 'LDAP_OPT_' . strtoupper($ldapOption);
                ldap_set_option($this->bindProvider->getLinkIdentifier(), constant($constantName), $ldapOptionValue);
            }
        }
    }

    /**
     * Authenticate a username / password against the LDAP server
     *
     * @param string $username
     * @param string $password
     * @return array Search result from LDAP
     * @throws Exception
     */
    public function authenticate($username, $password)
    {
        try {
            $this->ldapConnect();
            $this->bindProvider->bind($username, $password);
            $entries = $this->getUserEntries($username);
            if (!empty($entries)) {
                $this->bindProvider->verifyCredentials($entries[0]['dn'], $password);
                // get all entries in the second run in the case of anonymous bind
                $anonymousBind = Arrays::getValueByPath($this->options, 'bind.anonymous');
                if ($anonymousBind === true) {
                    $entries = $this->getUserEntries($username);
                } else {
                    $this->bindProvider->bind($username, $password);
                }
            }
            return $entries[0];
        } catch (\Exception $exception) {
            throw new Exception('Error during LDAP server authentication: ' . $exception->getMessage(), 1323167213);
        }
    }

    /**
     * Get the user entities from the LDAP server
     * At least the dn should be returned.
     *
     * @param $username
     * @return array
     * @throws Exception
     */
    public function getUserEntries($username)
    {
        $searchResult = @ldap_search(
            $this->bindProvider->getLinkIdentifier(),
            $this->options['baseDn'],
            str_replace(
                '?',
                $this->bindProvider->getFilteredUsername($username),
                $this->options['filter']['account']
            )
        );
        if ($searchResult) {
            $entries = ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult);

            if ($entries['count'] === 1) {
                return $entries;
            }
        } else {
            throw new Exception('Error during LDAP user search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443798372);
        }
    }

    /**
     * @param string $username
     * @return array
     * @throws Exception
     */
    public function getGroupMembership($username)
    {
        $groups = array();
        $groupFilterOptions = Arrays::arrayMergeRecursiveOverrule(
            array('dn' => 'dn', 'cn' => 'cn'),
            isset($this->options['group']) && is_array($this->options['group']) ? $this->options['group'] : array()
        );

        if (!isset($groupFilterOptions['membershipFilter'])) {
            return $groups;
        }

        $searchResult = @ldap_search(
            $this->bindProvider->getLinkIdentifier(),
            $this->options['baseDn'],
            sprintf($groupFilterOptions['membershipFilter'], $this->bindProvider->getFilteredUsername($username))
        );

        if ($searchResult) {
            foreach (ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult) as $group) {
                if (is_array($group) && isset($group[$groupFilterOptions['dn']])) {
                    $groups[$group[$groupFilterOptions['dn']]] = $group[$groupFilterOptions['cn']][0];
                }
            }
        } else {
            throw new Exception('Error during LDAP group search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443476083);
        }

        return $groups;
    }

    /**
     * Check if the server is online / can be reached
     *
     * @return boolean
     */
    public function isServerOnline()
    {
        return ServerStatusUtility::isServerOnline($this->options['host'], $this->options['port']);
    }

    /**
     * @return resource
     */
    public function getConnection()
    {
        $this->ldapConnect();
        return $this->bindProvider->getLinkIdentifier();
    }

    /**
     * @param string|null $username
     * @param string|null $password
     * @return void
     * @throws Exception
     */
    public function bind($username = null, $password = null)
    {
        $this->ldapConnect();
        $this->bindProvider->bind($username, $password);
    }
}

