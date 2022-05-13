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

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Configuration\Exception\InvalidConfigurationTypeException;
use Neos\Flow\Persistence\Exception\IllegalObjectTypeException;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\PersistedUsernamePasswordProvider;
use Neos\Flow\Security\Authentication\Token\UsernamePassword;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception as SecurityException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Security\Exception\MissingConfigurationException;
use Neos\Flow\Security\Exception\NoSuchRoleException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Ldap\Service\DirectoryService;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Exception\LdapException;

/**
 * Ldap Authentication provider
 *
 * @Flow\Scope("prototype")
 */
class LdapProvider extends PersistedUsernamePasswordProvider
{
    /**
     * @var DirectoryService|null
     */
    protected $directoryService;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\InjectConfiguration(path="roles", package="Neos.Ldap")
     * @var array
     */
    protected array $rolesConfiguration = [];

    /**
     * Authenticate the current token. If it's not possible to connect to the LDAP server the provider tries to
     * authenticate against cached credentials in the database that were cached on the last successful login for the
     * user to authenticate.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws MissingConfigurationException
     * @throws UnsupportedAuthenticationTokenException
     * @throws InvalidConfigurationTypeException
     * @throws SecurityException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof UsernamePassword)) {
            throw new UnsupportedAuthenticationTokenException(
                'This provider cannot authenticate the given token.',
                1217339840
            );
        }

        $credentials = $authenticationToken->getCredentials();
        if (!\is_array($credentials) || !isset($credentials['username'], $credentials['password'])) {
            try {
                $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            } catch (InvalidAuthenticationStatusException $exception) {
                // This exception is never thrown
            }
            return;
        }
        // Retrieve account for the credentials
        $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName(
            $credentials['username'],
            $this->name
        );

        try {
            $this->directoryService = new DirectoryService(
                $this->options,
                $credentials['username'],
                $credentials['password']
            );
            $ldapUserData = $this->directoryService->getUserData($credentials['username']);

            // Create account if not existent
            if ($account === null) {
                $account = $this->createAccount($credentials, $ldapUserData);
                if ($account === null) {
                    throw new LdapException('Only existing accounts allowed');
                }
                $this->emitAccountCreated($account, $ldapUserData);
            }
        } catch (ConnectionException|LdapException $exception) {
            try {
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                if ($account !== null) {
                    $account->authenticationAttempted(TokenInterface::WRONG_CREDENTIALS);
                    $this->accountRepository->update($account);
                    $this->persistenceManager->allowObject($account);
                }
            } catch (InvalidAuthenticationStatusException|IllegalObjectTypeException $exception) {
                // This exception is never thrown
            }
            return;
        }

        // Map security roles to account
        $this->setRoles($account, $ldapUserData);
        $this->emitRolesSet($account, $ldapUserData);

        // Mark authentication successful
        try {
            $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $this->accountRepository->update($account);
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        } catch (InvalidAuthenticationStatusException|IllegalObjectTypeException $exception) {
            // This exception is never thrown
        }
        $this->persistenceManager->allowObject($account);
        $authenticationToken->setAccount($account);
        $this->emitAccountAuthenticated($account, $ldapUserData);
    }

    /**
     * @Flow\Signal
     * @param Account $account
     * @param string[][] $ldapUserData
     * @return void
     */
    public function emitAccountCreated(Account $account, array $ldapUserData): void
    {
    }

    /**
     * @Flow\Signal
     * @param Account $account
     * @param string[][] $ldapUserData
     * @return void
     */
    public function emitAccountAuthenticated(Account $account, array $ldapUserData): void
    {
    }

    /**
     * @Flow\Signal
     * @param Account $account
     * @param string[][] $ldapUserData
     * @return void
     */
    public function emitRolesSet(Account $account, array $ldapUserData): void
    {
    }

    /**
     * Create a new account for the given credentials. Return null if you do not want to create a new account, that is,
     * only authenticate existing accounts from the database and fail on new logins.
     *
     * @param string[] $credentials array containing username and password
     * @param string[][] $ldapUserData
     * @return Account|null
     */
    protected function createAccount(array $credentials, array $ldapUserData): ?Account
    {
        $account = new Account();
        $account->setAccountIdentifier($credentials['username']);
        $account->setAuthenticationProviderName($this->name);
        try {
            $this->accountRepository->add($account);
        } catch (IllegalObjectTypeException $exception) {
            // This exception is never thrown
        }
        return $account;
    }

    /**
     * @param Account $account
     * @return void
     */
    protected function resetRoles(Account $account): void
    {
        try {
            $account->setRoles([]);
        } catch (\InvalidArgumentException $exception) {
            // This exception is never thrown
        }
    }

    /**
     * Set all default roles
     *
     * @param Account $account
     * @return void
     * @throws InvalidConfigurationTypeException
     * @throws SecurityException
     */
    protected function setDefaultRoles(Account $account): void
    {
        if (!\is_array($this->rolesConfiguration['default'])) {
            return;
        }

        foreach ($this->rolesConfiguration['default'] as $roleIdentifier) {
            try {
                $account->addRole($this->policyService->getRole($roleIdentifier));
            } catch (\InvalidArgumentException $exception) {
                // This exception is never thrown
            } catch (NoSuchRoleException $exception) {
                // We ignore invalid roles
                // todo: logging
                continue;
            }
        }
    }

    /**
     * Sets the roles for the Ldap account
     *
     * Extend this Provider class and implement this method to update the party
     *
     * @param Account $account
     * @param string[][] $ldapUserData
     * @return void
     * @throws InvalidConfigurationTypeException
     * @throws SecurityException
     */
    protected function setRoles(Account $account, array $ldapUserData): void
    {
        $this->resetRoles($account);
        $this->setDefaultRoles($account);
        $this->setRolesByUserProperties($account, $ldapUserData);
        $this->setRolesByUserDn($account, $ldapUserData['dn'][0]);
        try {
            $this->setRolesByGroupDns($account, $this->directoryService->getGroupDnsOfUser($ldapUserData['dn'][0]));
        } catch (MissingConfigurationException|LdapException $exception) {
            // If groups cannot be retrieved, they won't get set
            // todo: logging
        }

        try {
            $this->accountRepository->update($account);
        } catch (IllegalObjectTypeException $exception) {
            // This exception is never thrown
        }
    }

    /**
     * Map configured roles based on group membership
     *
     * @param Account $account
     * @param string[] $groupDns
     * @return void
     * @throws InvalidConfigurationTypeException
     * @throws SecurityException
     */
    protected function setRolesByGroupDns(Account $account, array $groupDns): void
    {
        if (!\is_array($this->rolesConfiguration['groupMapping'])) {
            return;
        }

        foreach ($this->rolesConfiguration['groupMapping'] as $roleIdentifier => $roleGroupDns) {
            if (\array_intersect($groupDns, $roleGroupDns) !== []) {
                try {
                    $account->addRole($this->policyService->getRole($roleIdentifier));
                } catch (\InvalidArgumentException $exception) {
                    // This exception is never thrown
                } catch (NoSuchRoleException $exception) {
                    // We ignore invalid roles
                    // todo: logging
                    continue;
                }
            }
        }
    }

    /**
     * Map configured roles based on user dn
     *
     * @param Account $account
     * @param string $userDn
     * @return void
     * @throws InvalidConfigurationTypeException
     * @throws SecurityException
     */
    protected function setRolesByUserDn(Account $account, string $userDn): void
    {
        if (!\is_array($this->rolesConfiguration['userMapping'])) {
            return;
        }

        foreach ($this->rolesConfiguration['userMapping'] as $roleIdentifier => $roleUserDns) {
            if (\in_array($userDn, $roleUserDns, true)) {
                try {
                    $account->addRole($this->policyService->getRole($roleIdentifier));
                } catch (\InvalidArgumentException $exception) {
                    // This exception is never thrown
                } catch (NoSuchRoleException $exception) {
                    // We ignore invalid roles
                    // todo: logging
                    continue;
                }
            }
        }
    }

    /**
     * Map configured roles base on user properties
     *
     * @param Account $account
     * @param string[][] $ldapUserData
     * @return void
     * @throws InvalidConfigurationTypeException
     * @throws SecurityException
     */
    protected function setRolesByUserProperties(Account $account, array $ldapUserData): void
    {
        if (!\is_array($this->rolesConfiguration['propertyMapping'])) {
            return;
        }

        foreach ($this->rolesConfiguration['propertyMapping'] as $roleIdentifier => $propertyConditions) {
            try {
                $role = $this->policyService->getRole($roleIdentifier);
            } catch (NoSuchRoleException $e) {
                // We ignore invalid roles
                // todo: logging
                continue;
            }

            foreach ($propertyConditions as $propertyName => $conditions) {
                if (!isset($ldapUserData[$propertyName])) {
                    continue;
                }

                if (!\is_array($conditions)) {
                    $conditions = [$conditions];
                }
                foreach ($conditions as $condition) {
                    foreach ($ldapUserData[$propertyName] as $value) {
                        if ($value === $condition || @\preg_match($condition, $value) === 1) {
                            try {
                                $account->addRole($role);
                            } catch (\InvalidArgumentException $e) {
                                // This exception is never thrown
                            }
                            continue 4;
                        }
                    }
                }
            }
        }
    }
}
