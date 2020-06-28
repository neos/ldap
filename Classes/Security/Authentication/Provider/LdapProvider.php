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
use Neos\Flow\Security\Authentication\Provider\PersistedUsernamePasswordProvider;
use Neos\Flow\Security\Authentication\Token\UsernamePassword;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Ldap\Service\DirectoryService;

/**
 * Ldap Authentication provider
 *
 * @Flow\Scope("prototype")
 */
class LdapProvider extends PersistedUsernamePasswordProvider
{

    /**
     * @Flow\InjectConfiguration(path="roles", package="Neos.Ldap")
     * @var array
     */
    protected $rolesConfiguration;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @var DirectoryService
     */
    protected $directoryService;

    /**
     * @param string $name The name of this authentication provider
     * @param array $options Additional configuration options
     */
    public function __construct($name, array $options)
    {
        parent::__construct($name, $options);
        $this->directoryService = new DirectoryService($name, $options);
    }

    /**
     * Authenticate the current token. If it's not possible to connect to the LDAP server the provider
     * tries to authenticate against cached credentials in the database that were
     * cached on the last successful login for the user to authenticate.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws UnsupportedAuthenticationTokenException
     * @return void
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof UsernamePassword)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
        }

        $credentials = $authenticationToken->getCredentials();
        if (!is_array($credentials) || !isset($credentials['username'])) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            return;
        }

        try {
            $ldapUser = $this->directoryService->authenticate($credentials['username'], $credentials['password']);

            // Retrieve or create account for the credentials
            $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->name);
            if ($account === null) {
                $account = $this->createAccountForCredentials($credentials);
                $this->emitAccountCreated($account, $ldapUser);
            }

            // Map security roles to account
            $this->setRoles($account, $ldapUser);
            $this->emitRolesSet($account, $ldapUser);

            // Mark authentication successful
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
            $this->emitAccountAuthenticated($account, $ldapUser);
        } catch (\Exception $exception) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
        }
    }

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
        $account = new Account();
        $account->setAccountIdentifier($credentials['username']);
        $account->setAuthenticationProviderName($this->name);
        $this->accountRepository->add($account);
        return $account;
    }

    /**
     * Sets the roles for the Ldap account.
     * Extend this Provider class and implement this method to update the party
     *
     * @param Account $account
     * @param array $ldapSearchResult
     * @return void
     */
    protected function setRoles(Account $account, array $ldapSearchResult)
    {
        $this->setDefaultRoles($account);
        $this->setRolesMappedToUserDn($account, $ldapSearchResult);
        $this->setRolesBasedOnGroupMembership($account, $ldapSearchResult);

        $this->accountRepository->update($account);
    }

    /**
     * Set all default roles
     *
     * @param Account $account
     */
    protected function setDefaultRoles(Account $account)
    {
        if (!is_array($this->rolesConfiguration['default'])) {
            return;
        }

        foreach ($this->rolesConfiguration['default'] as $roleIdentifier) {
            $account->addRole($this->policyService->getRole($roleIdentifier));
        }
    }

    /**
     * Map configured roles based on user dn
     *
     * @param Account $account
     * @param array $ldapSearchResult
     */
    protected function setRolesMappedToUserDn(Account $account, array $ldapSearchResult)
    {
        if (!is_array($this->rolesConfiguration['userMapping'])) {
            return;
        }

        foreach ($this->rolesConfiguration['userMapping'] as $roleIdentifier => $userDns) {
            if (in_array($ldapSearchResult['dn'], $userDns)) {
                $account->addRole($this->policyService->getRole($roleIdentifier));
            }
        }
    }

    /**
     * Map configured roles based on group membership
     *
     * @param Account $account
     * @param array $ldapSearchResult
     */
    protected function setRolesBasedOnGroupMembership(Account $account, array $ldapSearchResult)
    {
        if (!is_array($this->rolesConfiguration['groupMapping'])) {
            return;
        }

        $memberOf = $this->directoryService->getMemberOf($ldapSearchResult['dn']);
        foreach ($this->rolesConfiguration['groupMapping'] as $roleIdentifier => $groupDns) {
            if (!empty(array_intersect($memberOf, $groupDns))) {
                $account->addRole($this->policyService->getRole($roleIdentifier));
            }
        }
    }

    /**
     * @param Account $account
     * @param array $ldapSearchResult
     * @return void
     * @Flow\Signal
     */
    public function emitAccountCreated(Account $account, array $ldapSearchResult)
    {
    }

    /**
     * @param Account $account
     * @param array $ldapSearchResult
     * @return void
     * @Flow\Signal
     */
    public function emitAccountAuthenticated(Account $account, array $ldapSearchResult)
    {
    }

    /**
     * @param Account $account
     * @param array $ldapSearchResult
     * @return void
     * @Flow\Signal
     */
    public function emitRolesSet(Account $account, array $ldapSearchResult)
    {
    }

}
