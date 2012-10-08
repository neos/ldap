<?php
namespace TYPO3\LDAP\Security\Authentication\Provider;

/*                                                                        *
 * This script belongs to the Flow package "TYPO3.LDAP".                  *
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU Lesser General Public License as published by the *
 * Free Software Foundation, either version 3 of the License, or (at your *
 * option) any later version.                                             *
 *                                                                        *
 * This script is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN-    *
 * TABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser       *
 * General Public License for more details.                               *
 *                                                                        *
 * You should have received a copy of the GNU Lesser General Public       *
 * License along with the script.                                         *
 * If not, see http://www.gnu.org/licenses/lgpl.html                      *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use TYPO3\Flow\Annotations as Flow;

use TYPO3\Flow\Security\Authentication\TokenInterface;

/**
 * LDAP Authentication provider
 *
 * @Flow\Scope("prototype")
 */
class LDAPProvider extends \TYPO3\Flow\Security\Authentication\Provider\PersistedUsernamePasswordProvider {

	/**
	 * @var \TYPO3\LDAP\Service\DirectoryService
	 */
	protected $directoryService;

	/**
	 * Constructor
	 *
	 * @param string $name The name of this authentication provider
	 * @param array $options Additional configuration options
	 * @return void
	 */
	public function __construct($name, array $options) {
		$this->name = $name;
		$this->directoryService = new \TYPO3\LDAP\Service\DirectoryService($name, $options);
	}

	/**
	 * Authenticate the current token. If it's not possible to connect to the LDAP server the provider
	 * tries to authenticate against cached credentials in the database that were
	 * cached on the last successful login for the user to authenticate.
	 *
	 * @param TYPO3\Flow\Security\Authentication\TokenInterface $authenticationToken The token to be authenticated
	 * @return void
	 */
	public function authenticate(TokenInterface $authenticationToken) {
		if (!($authenticationToken instanceof \TYPO3\Flow\Security\Authentication\Token\UsernamePassword)) {
			throw new \TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
		}

		$account = NULL;
		$credentials = $authenticationToken->getCredentials();

		if (is_array($credentials) && isset($credentials['username'])) {
			if ($this->directoryService->isServerOnline()) {
				try {
					$ldapUser = $this->directoryService->authenticate($credentials['username'], $credentials['password']);

					if ($ldapUser) {
						$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->name);
						if (empty($account)) {
							$account = new \TYPO3\Flow\Security\Account();
							$account->setAccountIdentifier($credentials['username']);
							$account->setAuthenticationProviderName($this->name);
							$this->accountRepository->add($account);

							$this->createParty($account, $ldapUser);
						}

						if ($account instanceof \TYPO3\Flow\Security\Account) {
							// Cache the password to have cached login if LDAP is unavailable
							$account->setCredentialsSource($this->hashService->generateHmac($credentials['password']));
							$authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
							$authenticationToken->setAccount($account);
						} elseif ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
							$authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
						}
					} else {
						$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
					}

				} catch (\Exception $exception) {
				}
			} else {
				$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->name);

					// Server not available, fallback to the cached password hash
				if ($account instanceof \TYPO3\Flow\Security\Account) {
					if ($this->hashService->validateHmac($credentials['password'], $account->getCredentialsSource())) {
						$authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
						$authenticationToken->setAccount($account);
					} else {
						$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
					}
				} elseif ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
					$authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
				}
			}
		} else {
			$authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
		}
	}

	/**
	 * Create a new party for a user's first login
	 * Extend this Provider class and implement this method to create a party
	 *
	 * @param \TYPO3\Flow\Security\Account $account The freshly created account that should be used for this party
	 * @param array $ldapSearchResult The first result returned by ldap_search
	 * @return void
	 */
	protected function createParty(\TYPO3\Flow\Security\Account $account, array $ldapSearchResult) {
	}

}

?>