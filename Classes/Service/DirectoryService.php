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
use Symfony\Component\Ldap\Adapter\ExtLdap\Adapter;
use Symfony\Component\Ldap\Ldap;

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
     * @var Ldap
     */
    protected $connection;

    /**
     * @var Ldap
     */
    protected $readConnection;

    /**
     * @param string $name
     * @param array $options
     * @throws Exception
     */
    public function __construct($name, array $options)
    {
        $this->name = $name;
        $this->options = $options;

        $this->ldapConnect();
    }

    /**
     * @return Ldap
     */
    public function getReadConnection()
    {
        if ($this->readConnection) {
            return $this->readConnection;
        }

        if (!$this->connection) {
            $this->ldapConnect();
        }

        $this->readConnection = clone $this->connection;
        if (!empty($this->options['connection']['bind'])) {
            $this->readConnection->bind(
                $this->options['connection']['bind']['dn'],
                $this->options['connection']['bind']['password']
            );
        }

        return $this->readConnection;
    }

    /**
     * Initialize the Ldap server connection
     *
     * Connect to the server and set communication options. Further bindings will be done
     * by a server specific bind provider.
     *
     * @throws Exception
     */
    protected function ldapConnect()
    {
        if ($this->connection) {
            return $this->connection;
        }

        $adapter = new Adapter($this->options['connection']['options']);
        $this->connection = new Ldap($adapter);
        return $this->connection;
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
        $result = $this->getReadConnection()
            ->query(
                $this->options['baseDn'],
                sprintf($this->options['query']['account'], $username),
                ['filter' => $this->options['filter']['account']]
            )
            ->execute()
            ->toArray();

        if (!isset($result[0])) {
            throw new \Exception('User not found');
        }

        $this->connection->bind($result[0]->getDn(), $password);

        $userData = ['dn' => $result[0]->getDn()];

        return $userData;
    }

    /**
     * @param string $dn  User or group DN.
     * @return array group  DN => CN mapping
     * @throws Exception
     */
    public function getMemberOf($dn)
    {
        try {
            $searchResult = $this->getReadConnection()
                ->query(
                    $this->options['baseDn'],
                    sprintf($this->options['query']['memberOf'], $dn),
                    ['filter' => $this->options['filter']['group']]
                )
                ->execute()
                ->toArray();
        } catch (\Exception $exception) {
            throw new Exception('Error during Ldap group search: ' . $exception->getMessage(), 1443476083);
        }

        return $searchResult;
    }

}
