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
use Neos\Flow\Log\SecurityLoggerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\PersistedUsernamePasswordProvider as PersistedUsernamePasswordProviderOrg;
use Neos\Flow\Security\Authentication\Token\UsernamePassword;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Ldap\Service\DirectoryService;
use Neos\Neos\Domain\Model\User;
use Neos\Neos\Domain\Service\UserService;
use Neos\ContentRepository\Domain\Model\Workspace;
use Neos\ContentRepository\Domain\Repository\WorkspaceRepository;
use Neos\Neos\Utility\User as UserUtility;

/**
 * Ldap Authentication provider
 *
 * @Flow\Scope("prototype")
 */
class PersistedUsernamePasswordProvider extends PersistedUsernamePasswordProviderOrg
{

    /**
     * @Flow\Inject
     * @var WorkspaceRepository
     */
    protected $workspaceRepository;

    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

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
     * @Flow\Inject
     * @var SecurityLoggerInterface
     */
    protected $logger;

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
            $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], 'Neos.Neos:Backend');
            if ($account === null) {
                $account = $this->createAccountForCredentials($credentials, $ldapUser);
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
            $this->logger->log('Authentication failed: ' . $exception->getMessage(), LOG_ALERT);
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
        }
    }

    /**
     * Creates a personal workspace for the given user's account if it does not exist already.
     *
     * @param User $user The new user to create a workspace for
     * @param Account $account The user's backend account
     * @throws IllegalObjectTypeException
     */
    protected function createPersonalWorkspace(User $user, Account $account)
    {
        $userWorkspaceName = UserUtility::getPersonalWorkspaceNameForUsername($account->getAccountIdentifier());
        $userWorkspace = $this->workspaceRepository->findByIdentifier($userWorkspaceName);
        if ($userWorkspace === null) {
            $liveWorkspace = $this->workspaceRepository->findByIdentifier('live');
            if (!($liveWorkspace instanceof Workspace)) {
                $liveWorkspace = new Workspace('live');
                $liveWorkspace->setTitle('Live');
                $this->workspaceRepository->add($liveWorkspace);
            }

            $userWorkspace = new Workspace($userWorkspaceName, $liveWorkspace, $user);
            $userWorkspace->setTitle((string)$user->getName());
            $this->workspaceRepository->add($userWorkspace);
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
    protected function createAccountForCredentials(array $credentials, array $ldapUser)
    {
        $user = $this->userService->getUser($credentials['username'], 'Neos.Neos:Backend');
        if ($user) {
            //update password
            $this->userService->setUserPassword($user, $credentials['password']);
            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($credentials['username'], 'Neos.Neos:Backend');
        } else {
            //add user
            $user = $this->userService->createUser(
                $credentials['username'],
                $credentials['password'],
                $ldapUser['givenname'][0],
                $ldapUser['sn'][0],
                $this->rolesConfiguration['default'],
                'Neos.Neos:Backend'
            );
            $this->persistenceManager->persistAll();

            //create workspace
            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($credentials['username'], 'Neos.Neos:Backend');
            $this->createPersonalWorkspace($user, $account);
        }
        // Set user deactivated to prevent login check from 'Neos.Neos:Backend' Provider for next login
        // so the credentials can be checked for each login by the Ldap connector
        $this->userService->deactivateUser($user);

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
