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
     * Bind to an ActiveDirectory server. Prefixes the username with a domain if configured.
     *
     * @param string $username
     * @param string $password
     * @throws Exception
     */
    public function bind($username, $password)
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

        $this->bindWithDn($username, $password);
    }

    /**
     * Return username in format used for directory search
     *
     * @param string $username
     * @return string
     */
    public function filterUsername($username)
    {
        if (!empty($this->options['domain'])) {
            $usernameSegments = explode('\\', $username);
            $usernameWithoutDomain = array_pop($usernameSegments);
            $username = $this->options['filter']['ignoreDomain'] ? $usernameWithoutDomain : addcslashes($username, '\\');
        }
        return $username;
    }

}

