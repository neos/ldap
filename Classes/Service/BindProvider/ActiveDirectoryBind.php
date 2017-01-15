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
 * Bind to an ActiveDirectory Server
 *
 * @Flow\Scope("prototype")
 */
class ActiveDirectoryBind extends AbstractBindProvider
{

    /**
     * Bind to an ActiveDirectory server
     *
     * Prefix the username with a domain if configured.
     *
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function bind($username, $password)
    {
        try {
            ldap_bind($this->linkIdentifier, $this->getUsername($username), $password);
        } catch (\Exception $exception) {
            throw new Exception('Could not bind to ActiveDirectory server. Error was: ' . $exception->getMessage(), 1327937215);
        }
    }

    /**
     * @param string $username
     * @return string
     */
    protected function getUsername($username)
    {
        if (!empty($this->options['domain'])) {
            if (!strpos($username, '\\')) {
                $username = $this->options['domain'] . '\\' . $username;
            }
        }
        if (!empty($this->options['usernameSuffix'])) {
            if (!strpos($username, '@')) {
                $username = $username . '@' . $this->options['usernameSuffix'];
            }
        }
        return $username;
    }

    /**
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function verifyCredentials($username, $password)
    {
        try {
            ldap_bind($this->linkIdentifier, $this->getUsername($username), $password);
        } catch (\Exception $exception) {
            throw new Exception('Could not verify credentials for dn: "' . $username . '"', 1327763970);
        }
    }

    /**
     * Return username in format used for directory search
     *
     * @param string $username
     * @return string
     */
    public function getFilteredUsername($username)
    {
        if (!empty($this->options['domain'])) {
            $usernameParts = explode('\\', $username);
            $usernameWithoutDomain = array_pop($usernameParts);
            return $this->options['filter']['ignoreDomain'] ? $usernameWithoutDomain : addcslashes($username, '\\');
        }
        return $username;
    }

}

