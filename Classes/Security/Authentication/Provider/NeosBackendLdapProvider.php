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

use Neos\Eel\CompilingEvaluator;
use Neos\Eel\Context;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Utility\Arrays;

/**
 * Ldap Authentication provider
 *
 * @Flow\Scope("prototype")
 */
class NeosBackendLdapProvider extends LdapProvider
{
    /**
     * @Flow\Inject
     * @var CompilingEvaluator
     */
    protected $eelEvaluator;

    /**
     * Create a new account for the given credentials. Return null if you
     * do not want to create a new account, that is, only authenticate
     * existing accounts from the database and fail on new logins.
     *
     * @param array $credentials array containing username and password
     * @param array $ldapSearchResult
     * @return Account
     */
    protected function createAccount(array $credentials, array $ldapSearchResult)
    {
        $mapping = Arrays::arrayMergeRecursiveOverrule(
            [
                'firstName' => 'user.givenName[0]',
                'lastName' => 'user.sn[0]'
            ],
            isset($this->options['mapping']) ? $this->options['mapping'] : []
        );

        $eelContext = new Context(['user' => $ldapSearchResult]);

        try {
            $firstName = $this->eelEvaluator->evaluate($mapping['firstName'], $eelContext);
            $lastName = $this->eelEvaluator->evaluate($mapping['lastName'], $eelContext);
        } catch (\Exception $exception) {
            // todo : add logging
            $firstName = 'none';
            $lastName = 'none';
        }

        $userService = new \Neos\Neos\Domain\Service\UserService();
        $user = $userService->createUser(
            $credentials['username'],
            '',
            $firstName,
            $lastName,
            [],
            $this->name
        );

        return $user->getAccounts()->get(0);
    }
}
