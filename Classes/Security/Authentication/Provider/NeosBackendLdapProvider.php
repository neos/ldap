<?php
namespace Neos\Ldap\Security\Authentication\Provider;

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
use Neos\Flow\Security\Account;

/**
 * Ldap Authentication provider
 *
 * @Flow\Scope("prototype")
 */
class NeosBackendLdapProvider extends LdapProvider
{

    /**
     * Create a new account for the given credentials. Return null if you
     * do not want to create a new account, that is, only authenticate
     * existing accounts from the database and fail on new logins.
     *
     * @param array $credentials array containing username and password
     * @return Account
     */
    protected function createAccountForCredentials(array $credentials)
    {
        $userService = new \Neos\Neos\Domain\Service\UserService();
        $user = $userService->createUser(
            $credentials['username'],
            '',
            $credentials['username'],
            $credentials['username'],
            [],
            $this->name
        );

        return $user->getAccounts()->get(0);
    }

}
