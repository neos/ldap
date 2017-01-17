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

/**
 * Bind to an OpenLdap Server
 *
 * @Flow\Scope("prototype")
 */
abstract class AbstractBindProvider implements BindProviderInterface
{

    /**
     * @var resource
     */
    protected $linkIdentifier;

    /**
     * @var array
     */
    protected $options;

    /**
     * @param resource $linkIdentifier
     * @param array $options
     */
    public function __construct($linkIdentifier, array $options)
    {
        $this->linkIdentifier = $linkIdentifier;
        $this->options = $options;
    }

    /**
     * Return the ldap connection identifier.
     *
     * @return resource
     */
    public function getLinkIdentifier()
    {
        return $this->linkIdentifier;
    }

    /**
     * Return the filtered username for directory search.
     *
     * @param string $username
     * @return string
     */
    public function filterUsername($username)
    {
        return $username;
    }

    /**
     * Bind to the directory server. Returns void but throws exception on failure.
     *
     * @param string $userDn The DN of the user.
     * @param string $password The user's password.
     * @throws Exception
     */
    protected function bindWithDn($userDn, $password)
    {
        try {
            $bindIsSuccessful = ldap_bind($this->linkIdentifier, $userDn, $password);
        } catch (\Exception $exception) {
            $bindIsSuccessful = false;
        }

        if (!$bindIsSuccessful) {
            throw new Exception('Failed to bind with DN: "' . $userDn . '"', 1327763970);
        }
    }

    /**
     * Bind anonymously to the directory server. Returns void but throws exception on failure.
     *
     * @throws Exception
     */
    protected function bindAnonymously()
    {
        try {
            $bindIsSuccessful = ldap_bind($this->linkIdentifier);
        } catch (\Exception $exception) {
            $bindIsSuccessful = false;
        }

        if (!$bindIsSuccessful) {
            throw new Exception('Failed to bind anonymously', 1327763970);
        }
    }

    /**
     * Verify the given user is known to the directory server and has valid credentials.
     * Does not return output but throws an exception if the credentials are invalid.
     *
     * @param string $dn The DN of the user.
     * @param string $password The user's password.
     * @throws Exception
     */
    public function verifyCredentials($dn, $password)
    {
        $this->bindWithDn($dn, $password);
    }

}
