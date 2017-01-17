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
use Neos\Ldap\Utility\ServerStatusUtility;

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
     * Set the Ldap options configured in the settings.
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
        foreach ($this->options['ldapOptions'] as $ldapOption => $value) {
            $constantName = 'LDAP_OPT_' . strtoupper($ldapOption);
            ldap_set_option($this->bindProvider->getLinkIdentifier(), constant($constantName), $value);
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
        $this->bind($username, $password);
        
        $searchResult = @ldap_search(
            $this->bindProvider->getLinkIdentifier(),
            $this->options['baseDn'],
            sprintf($this->options['filter']['account'], $this->bindProvider->getFilteredUsername($username))
        );

        if (!$searchResult) {
            throw new Exception('Error during Ldap user search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443798372);
        }

        return current(ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult)) ?: null;
    }

    /**
     * @param string $dn  User or group DN.
     * @return array group  DN => CN mapping
     * @throws Exception
     */
    public function getMemberOf($dn)
    {
        $searchResult = @ldap_search(
            $this->bindProvider->getLinkIdentifier(),
            $this->options['baseDn'],
            sprintf($this->options['filter']['memberOf'], $dn)
        );

        if (!$searchResult) {
            throw new Exception('Error during Ldap group search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443476083);
        }

        return array_map(
            function (array $memberOf) { return $memberOf['dn']; },
            ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult)
        );
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

