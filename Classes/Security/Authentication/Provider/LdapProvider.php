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
use Neos\Flow\Log\SecurityLoggerInterface;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
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
     * @Flow\InjectConfiguration(path="defaultContext", package="Neos.Ldap")
     * @var array
     */
    protected $defaultContext;

    /**
     * @Flow\InjectConfiguration(path="roles", package="Neos.Ldap")
     * @var array
     */
    protected $rolesConfiguration;

    /**
     * @Flow\InjectConfiguration(path="party", package="Neos.Ldap")
     * @var array
     */
    protected $partyConfiguration;

    /**
     * @Flow\Inject
     * @var CompilingEvaluator
     */
    protected $eelEvaluator;

    /**
     * @Flow\Inject
     * @var ObjectManagerInterface
     */
    protected $objectManager;

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
     * Authenticate the current token. If it's not possible to connect to the Ldap server the provider
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

        $account = null;
        $credentials = $authenticationToken->getCredentials();

        if (is_array($credentials) && isset($credentials['username'])) {
            try {
                $ldapUser = $this->directoryService->authenticate($credentials['username'], $credentials['password']);
                if ($ldapUser) {
                    $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->name);
                    $newlyCreatedAccount = false;
                    if ($account === null) {
                        $account = new Account();
                        $account->setAccountIdentifier($credentials['username']);
                        $account->setAuthenticationProviderName($this->name);

                        $this->createParty($account, $ldapUser);

                        $this->accountRepository->add($account);
                        $newlyCreatedAccount = true;
                    }

                    if ($account instanceof Account) {
                        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                        $authenticationToken->setAccount($account);

                        $this->setRoles($account, $ldapUser);
                        $this->emitRolesSet($account, $ldapUser);
                        if ($newlyCreatedAccount === false) {
                            $this->updateParty($account, $ldapUser);
                        }
                        $this->emitAccountAuthenticated($account, $ldapUser);
                        $this->accountRepository->update($account);

                    } elseif ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
                        $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
                    }
                } else {
                    $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                }
            } catch (\Exception $exception) {
                $this->logger->log('Authentication failed: ' . $exception->getMessage(), LOG_ALERT);
            }
        } else {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
        }
    }

    /**
     * Create a new party for a user's first login
     * Extend this Provider class and implement this method to create a party
     *
     * @param Account $account The freshly created account that should be used for this party
     * @param array $ldapSearchResult The first result returned by ldap_search
     * @return void
     */
    protected function createParty(Account $account, array $ldapSearchResult)
    {
    }

    /**
     * Update the party for a user on subsequent logins
     * Extend this Provider class and implement this method to update the party
     *
     * @param Account $account The account with the party
     * @param array $ldapSearchResult
     * @return void
     */
    protected function updateParty(Account $account, array $ldapSearchResult)
    {
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
        if (is_array($this->rolesConfiguration)) {
            $contextVariables = array(
                'ldapUser' => $ldapSearchResult,
            );
            if (isset($this->defaultContext) && is_array($this->defaultContext)) {
                foreach ($this->defaultContext as $contextVariable => $objectName) {
                    $object = $this->objectManager->get($objectName);
                    $contextVariables[$contextVariable] = $object;
                }
            }

            foreach ($this->rolesConfiguration['default'] as $roleIdentifier) {
                $role = $this->policyService->getRole($roleIdentifier);
                $account->addRole($role);
            }

            $eelContext = new Context($contextVariables);
            if (isset($this->partyConfiguration['dn'])) {
                $dn = $this->eelEvaluator->evaluate($this->partyConfiguration['dn'], $eelContext);
                foreach ($this->rolesConfiguration['userMapping'] as $roleIdentifier => $userDns) {
                    if (in_array($dn, $userDns)) {
                        $role = $this->policyService->getRole($roleIdentifier);
                        $account->addRole($role);
                    }
                }
            } elseif (!empty($this->rolesConfiguration['userMapping'])) {
                $this->logger->log('User mapping found but no party mapping for dn set', LOG_ALERT);
            }

            if (isset($this->partyConfiguration['username'])) {
                $username = $this->eelEvaluator->evaluate($this->partyConfiguration['username'], $eelContext);
                $groupMembership = $this->directoryService->getGroupMembership($username);
                foreach ($this->rolesConfiguration['groupMapping'] as $roleIdentifier => $remoteRoleIdentifiers) {
                    foreach ($remoteRoleIdentifiers as $remoteRoleIdentifier) {
                        $role = $this->policyService->getRole($roleIdentifier);

                        if (isset($groupMembership[$remoteRoleIdentifier])) {
                            $account->addRole($role);
                        }
                    }
                }
            } elseif (!empty($this->rolesConfiguration['groupMapping'])) {
                $this->logger->log('Group mapping found but no party mapping for username set', LOG_ALERT);
            }
        }
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
