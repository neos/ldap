<?php
namespace Neos\Ldap\Utility;

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
 * A utility for server status related checks
 *
 * @Flow\Scope("prototype")
 */
class ServerStatusUtility
{

    /**
     * Check if the server is online / can be reached
     * TODO: make a fancy version of this method
     *
     * @return boolean
     */
    public static function isServerOnline($host, $port)
    {
        try {
            fsockopen(
                $host,
                $port,
                $errorNumber,
                $errorString,
                5
            );
            return true;
        } catch (\Exception $exception) {
            return false;
        }
    }

}

