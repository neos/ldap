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

/**
 * Interface for binding.
 */
interface BindProviderInterface
{

    /**
     * The link identifier to connect to the Ldap server.
     *
     * @return resource
     */
    public function getLinkIdentifier();

    /**
     * Bind to the server as defined by the settings
     *
     * @param $username
     * @param $password
     * @throws Exception
     */
    public function bind($username, $password);

    /**
     * Verify the given user is known to the directory server and has valid credentials.
     * Does not return output but throws an exception if the credentials are invalid.
     *
     * @param string $dn The DN of the user.
     * @param string $password The user's password.
     * @throws Exception
     */
    public function verifyCredentials($dn, $password);

    /**
     * Get a filtered username.
     *
     * @param $username
     * @return string
     */
    public function filterUsername($username);

}

