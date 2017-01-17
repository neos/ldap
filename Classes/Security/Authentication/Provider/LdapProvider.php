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
        // we can only authenticate users by password
        if (!($authenticationToken instanceof UsernamePassword)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
        }
        
        // do not accept empty or malformed credentials
        $credentials = $authenticationToken->getCredentials();
        if (!is_array($credentials) || !isset($credentials['username'])) {
            return $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
        }

        // retrieve user data from the remote directory server
        try {
            $ldapUser = null;
            $ldapUser = $this->directoryService->authenticate($credentials['username'], $credentials['password']);
        } catch (\Exception $exception) {
            $this->logger->log('Authentication failed: ' . $exception->getMessage(), LOG_ALERT);
        }

        // fail authentication if the directory server does not know any user with the given credentials
        if ($ldapUser === null) {
            return $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
        }

        // retrieve or create account for the credentials
        $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->name);
        if ($account === null) {
            $account = $this->createAccountForCredentials($credentials);

            // fail authentication if no account was found and none was created
            if ($account === null) {
                return $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            } 
            
            $this->emitAccountCreated($account, $ldapUser);
        }

        // map user and group dns to security roles
        $this->setRoles($account, $ldapUser);
        $this->emitRolesSet($account, $ldapUser);

        // mark authentication successful
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        $authenticationToken->setAccount($account);
        $this->emitAccountAuthenticated($account, $ldapUser);
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
        // map all default roles to the account
        foreach ($this->rolesConfiguration['default'] as $roleIdentifier) {
            $account->addRole($this->policyService->getRole($roleIdentifier));
        }
        
        // map users dns to roles
        foreach ($this->rolesConfiguration['userMapping'] as $roleIdentifier => $userDns) {
            if (in_array($ldapSearchResult['dn'], $userDns)) {
                $account->addRole($this->policyService->getRole($roleIdentifier));
            }
        }
        
        // map group dns to roles
        $memberOf = $this->directoryService->getMemberOf($ldapSearchResult['dn']);
        foreach ($this->rolesConfiguration['groupMapping'] as $roleIdentifier => $groupDns) {
            if (!empty(array_intersect($memberOf, $groupDns))) {
                $account->addRole($this->policyService->getRole($roleIdentifier));
            }
        }

        // persist role changes
        $this->accountRepository->update($account);
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
