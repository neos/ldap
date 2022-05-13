<?php
declare(strict_types=1);
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
use Neos\Neos\Domain\Service\UserService;
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
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    /**
     * @inheritdoc
     */
    protected function createAccount(array $credentials, array $ldapUserData): ?Account
    {
        $mapping = Arrays::arrayMergeRecursiveOverrule(
            [
                'firstName' => 'user.givenName[0]',
                'lastName' => 'user.sn[0]',
            ],
            $this->options['mapping'] ?? []
        );
        $eelContext = new Context(['user' => $ldapUserData]);

        try {
            $firstName = $this->eelEvaluator->evaluate($mapping['firstName'], $eelContext);
        } catch (\Exception $exception) {
            // todo: logging
            $firstName = 'none';
        }
        try {
            $lastName = $this->eelEvaluator->evaluate($mapping['lastName'], $eelContext);
        } catch (\Exception $exception) {
            // todo: logging
            $lastName = 'none';
        }

        $user = $this->userService->createUser(
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
