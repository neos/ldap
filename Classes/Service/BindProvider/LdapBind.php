<?php
namespace Neos\Ldap\Service\BindProvider;

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

/**
 * Bind to an OpenLdap Server
 *
 * @Flow\Scope("prototype")
 */
class LdapBind extends AbstractBindProvider
{

    /**
     * Bind to an ldap server in three different ways.
     *
     * Settings example for anonymous binding (dn and password will be ignored):
     *   ...
     *   bind:
     *       anonymous: TRUE
     *   filter:
     *       account: '(uid=?)'
     *
     * Settings example for binding with rootDN and admin password:
     *   ...
     *   bind:
     *       dn: 'uid=admin,dc=example,dc=com'
     *       password: 'secret'
     *   filter:
     *       account: '(uid=?)'
     *
     * Settings example for binding with userid and password:
     *   ...
     *   bind:
     *       dn: 'uid=?,ou=Users,dc=example,dc=com'
     *   filter:
     *       account: '(uid=?)'
     *
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function bind($username, $password)
    {
        try {
            if ($username !== null && $password !== null) {
                // This is a fallback to the original usage of bind.dn, usage of user.dn is preferred
                if (isset($this->options['user']['dn'])) {
                    $bindDn = str_replace('?', $username, $this->options['user']['dn']);
                } else {
                    $bindDn = str_replace('?', $username, $this->options['bind']['dn']);
                }

                ldap_bind($this->linkIdentifier, $bindDn, $password);
                return;
            }

            if ($username === null && $password === null && isset($this->options['bind']['anonymous']) && $this->options['bind']['anonymous'] === true) {
                ldap_bind($this->linkIdentifier);
                return;
            }

            if ($username === null && $password === null) {
                ldap_bind($this->linkIdentifier, $this->options['bind']['dn'], $this->options['bind']['password']);
                return;
            }

            throw new Exception('Could not bind to Ldap server', 1327748989);
        } catch (\Exception $exception) {
            throw new Exception('Could not bind to Ldap server. Error was: ' . $exception->getMessage(), 1327748989);
        }
    }

    /**
     * Bind by $username and $password
     *
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function verifyCredentials($username, $password)
    {
        try {
            $ldapBindResult = ldap_bind($this->linkIdentifier, $username, $password);
            if ($ldapBindResult === false) {
                throw new Exception('Could not verify credentials for dn: "' . $username . '"', 1327749076);
            }
        } catch (\Exception $exception) {
            throw new Exception('Could not verify credentials for dn: "' . $username . '"', 1327749076);
        }
    }

}
