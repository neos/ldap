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
     * The link identifier to connect to the Ldap server
     *
     * @return resource
     */
    public function getLinkIdentifier();

    /**
     * Bind to the server as defined by the settings
     *
     * @param $username
     * @param $password
     */
    public function bind($username, $password);

    /**
     * Bind by dn and password
     *
     * @param $dn
     * @param $password
     */
    public function verifyCredentials($dn, $password);

    /**
     * Get a filtered username
     *
     * @param $username
     */
    public function getFilteredUsername($username);
}

