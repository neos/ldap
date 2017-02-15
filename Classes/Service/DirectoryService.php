<?php
namespace Neos\Ldap\Service;

/*
 * This file is part of the Neos.Ldap package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Error\Exception;
use Neos\Utility\Arrays;
use Neos\Ldap\Service\BindProvider\BindProviderInterface;

/**
 * A simple Ldap authentication service
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
            throw new Exception('PHP is not compiled with Ldap support', 1305406047);
        }
    }

    /**
     * Initialize the Ldap server connection
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
            throw new Exception('Could not connect to Ldap server', 1326985286);
        }
    }

    /**
     * Set the Ldap options configured in the settings
     *
     * Loops over the ldapOptions array, and finds the corresponding Ldap option by prefixing
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
     * Authenticate a username / password against the Ldap server
     *
     * @param string $username
     * @param string $password
     * @return array Search result from Ldap
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
            throw new Exception('Error during Ldap server authentication: ' . $exception->getMessage(), 1323167213);
        }
    }

    /**
     * Get the user entities from the Ldap server
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
            str_replace(
                '?',
                $this->bindProvider->getFilteredUsername($username),
                $this->options['baseDn']
            ),
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
            throw new Exception('Error during Ldap user search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443798372);
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
            str_replace(
                '?',
                $this->bindProvider->getFilteredUsername($username),
                $this->options['baseDn']
            ),
            sprintf($groupFilterOptions['membershipFilter'], $this->bindProvider->getFilteredUsername($username))
        );

        if ($searchResult) {
            foreach (ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult) as $group) {
                if (is_array($group) && isset($group[$groupFilterOptions['dn']])) {
                    $groups[$group[$groupFilterOptions['dn']]] = $group[$groupFilterOptions['cn']][0];
                }
            }
        } else {
            throw new Exception('Error during Ldap group search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443476083);
        }

        return $groups;
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

