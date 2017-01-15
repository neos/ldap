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
     * @return resource
     */
    public function getLinkIdentifier()
    {
        return $this->linkIdentifier;
    }

    /**
     * Return the filtered username for directory search
     * overwrite for special needs
     *
     * @param string $username
     * @return string
     */
    public function getFilteredUsername($username)
    {
        return $username;
    }

}
