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
use Neos\Flow\Security\Exception\MissingConfigurationException;
use Neos\Utility\Arrays;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Exception\DriverNotFoundException;
use Symfony\Component\Ldap\Exception\LdapException;
use Symfony\Component\Ldap\Exception\NotBoundException;
use Symfony\Component\Ldap\Ldap;

/**
 * A simple Ldap authentication service
 * @Flow\Scope("prototype")
 */
class DirectoryService
{
    /**
     * @var Ldap
     */
    protected $ldap;

    /**
     * @var mixed[]
     */
    protected $options;

    /**
     * @param mixed[] $options
     * @param string|null $username
     * @param string|null $password
     * @throws ConnectionException
     */
    public function __construct(array $options, string $username = null, string $password = null)
    {
        $this->options = $options;

        $this->ldapConnect();
        $this->ldapBind($username, $password);
    }

    /**
     * @param string $userDn User DN
     * @return string[] Group DNs
     * @throws MissingConfigurationException
     * @throws LdapException
     */
    public function getGroupDnsOfUser(string $userDn) : array
    {
        if (!isset($this->options['queries']['group']['baseDn'], $this->options['queries']['group']['query'])) {
            throw new MissingConfigurationException('Both baseDn and query have to be set for queries.group');
        }

        $entries = $this->query(
            $this->options['queries']['group']['baseDn'],
            sprintf($this->options['queries']['group']['query'], $userDn),
            ['dn']
        );

        $groupDns = [];
        foreach ($entries as $entry) {
            $groupDns[] = $entry->getDn();
        }

        return $groupDns;
    }

    /**
     * Get account data from ldap server
     *
     * @param string $username
     * @return string[][] Search result from Ldap
     * @throws MissingConfigurationException
     * @throws LdapException
     */
    public function getUserData(string $username) : array
    {
        if (!isset($this->options['queries']['account']['baseDn'], $this->options['queries']['account']['query'])) {
            throw new MissingConfigurationException('Both baseDn and query have to be set for queries.account');
        }

        $entries = $this->query(
            $this->options['queries']['account']['baseDn'],
            sprintf($this->options['queries']['account']['query'], $username),
            $this->options['attributesFilter'] ?? []
        );
        if ($entries === []) {
            throw new LdapException('User not found');
        }

        return Arrays::arrayMergeRecursiveOverrule($entries[0]->getAttributes(), ['dn' => [$entries[0]->getDn()]]);
    }

    /**
     * @param string $baseDn
     * @param string $queryString
     * @param string[]|null $filter
     * @return Entry[]
     * @throws LdapException
     */
    public function query(string $baseDn, string $queryString, array $filter = null) : array
    {
        $query = $this->ldap->query($baseDn, $queryString, ['filter' => $filter ?? []]);
        /** @var Entry[] $entries */
        try {
            $entries = $query->execute()->toArray();
        } catch (NotBoundException $exception) {
            // This exception should never be thrown, since we bind in constructor
        }
        return $entries;
    }

    /**
     * @param string|null $username
     * @param string|null $password
     * @return void
     * @throws ConnectionException
     */
    protected function ldapBind(string $username = null, string $password = null)
    {
        $this->ldap->bind(
            (isset($this->options['bind']['dn'])
                ? sprintf($this->options['bind']['dn'], $username ?? '')
                : null
            ),
            $this->options['bind']['password'] ?? $password
        );
    }

    /**
     * Initialize the Ldap server connection
     *
     * Connect to the server and set communication options. Further bindings will be done by a server specific bind
     * provider.
     *
     * @return void
     */
    protected function ldapConnect()
    {
        try {
            $this->ldap = Ldap::create('ext_ldap', $this->options['connection'] ?? []);
        } catch (DriverNotFoundException $e) {
            // since we use the default driver, this cannot happen
        }
    }
}
