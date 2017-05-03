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
use Neos\Utility\Arrays;

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
     *
     * Settings example for binding with service account and its password:
     *   ...
     *   bind:
     *       dn: 'uid=admin,dc=example,dc=com'
     *       password: 'secret'
     *
     * Settings example for binding with user ID and password (the %s will be replaced by user ID):
     *   ...
     *   bind:
     *       dn: 'uid=%s,ou=Users,dc=example,dc=com'
     *
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function bind($username, $password)
    {
        $bindDn = Arrays::getValueByPath($this->options, 'bind.dn');
        if (!empty($username) && !empty($password)) {
            // if credentials are given, use them to authenticate
            $this->bindWithDn(sprintf($bindDn, $username), $password);
            return;
        }

        $bindPassword = Arrays::getValueByPath($this->options, 'bind.password');
        if (!empty($bindPassword)) {
            // if the settings specify a bind password, we are safe to assume no anonymous authentication is needed
            $this->bindWithDn($bindDn, $bindPassword);
        }

        $anonymousBind = Arrays::getValueByPath($this->options, 'bind.anonymous');
        if ($anonymousBind === true) {
            // if allowed, bind without username or password
            $this->bindAnonymously();
        }
    }

}
