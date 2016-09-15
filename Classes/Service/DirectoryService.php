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
use Neos\Ldap\Service\BindProvider\ActiveDirectoryBind;
use Neos\Ldap\Service\BindProvider\LdapBind;
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

        $bindProviderClass = LdapBind::class;
        $connectionType = Arrays::getValueByPath($this->options, 'type');
        if ($connectionType === 'ActiveDirectory') {
            $bindProviderClass = ActiveDirectoryBind::class;
        }
        if (!class_exists($bindProviderClass)) {
            throw new Exception("Bind provider '$bindProviderClass' for the service '$this->name' could not be resolved.", 1327756744);
        }

        $connection = ldap_connect($this->options['host'], $this->options['port']);
        $this->bindProvider = new $bindProviderClass($connection, $this->options);

        $this->setLdapOptions();
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
            sprintf($this->options['baseDn'], $this->bindProvider->filterUsername($username)),
            sprintf($this->options['filter']['account'], $this->bindProvider->filterUsername($username))
        );

        if (!$searchResult) {
            throw new Exception('Error during Ldap user search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443798372);
        }

        $entries = ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult);
        if (empty($entries) || !isset($entries[0])) {
            throw new Exception('Error while authenticating: authenticated user could not be fetched from the directory', 1488289104);
        }

        return $entries[0];
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

    /**
     * @param string $dn  User or group DN.
     * @return array group  DN => CN mapping
     * @throws Exception
     */
    public function getMemberOf($dn)
    {
        $searchResult = @ldap_search(
            $this->bindProvider->getLinkIdentifier(),
            sprintf($this->options['baseDn'], $this->bindProvider->filterUsername($username)),
            sprintf($this->options['filter']['memberOf'], $dn)
        );

        if (!$searchResult) {
            throw new Exception('Error during Ldap group search: ' . ldap_errno($this->bindProvider->getLinkIdentifier()), 1443476083);
        }

        return array_map(
            function (array $memberOf) { return $memberOf['dn']; },
            array_filter(
                ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult),
                function ($element) { return is_array($element); }
            )
        );
    }

}
