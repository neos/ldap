<?php
declare(ENCODING = 'utf-8');
namespace F3\LDAP\Security\Authentication\Provider;

/**
 * LDAP Authentication provider
 *
 * @license http://www.gnu.org/licenses/lgpl.html GNU Lesser General Public License, version 3 or later
 * @scope prototype
 */
class LDAPProvider extends \F3\FLOW3\Security\Authentication\Provider\PersistedUsernamePasswordProvider {

	/**
	 * @var \F3\LDAP\Domain\Repository\AccountRepository
	 * @inject
	 */
	protected $accountRepository;

	/**
	 * @var \F3\LDAP\Service\LDAP
	 */
	protected $ldapService;

	/**
	 * Constructor
	 *
	 * @param string $name The name of this authentication provider
	 * @param array $options Additional configuration options
	 * @return void
	 * @author Rens Admiraal <rens.admiraal@typo3.org>
	 */
	public function __construct($name, array $options) {
		$this->name = $name;
		$this->ldapService = new \F3\LDAP\Service\LDAP($options);
	}

	/**
	 * Authenticate the current token. If it's not possible to connect to the LDAP server the provider
	 * tries to authenticate against cached credentials in the database (cached on the last succesful login
	 * for the user to authenticate).
	 *
	 * @param F3\FLOW3\Security\Authentication\TokenInterface $authenticationToken The token to be authenticated
	 * @return void
	 * @author Rens Admiraal <rens.admiraal@typo3.org>
	 */
	public function authenticate(\F3\FLOW3\Security\Authentication\TokenInterface $authenticationToken) {
		if (!($authenticationToken instanceof \F3\FLOW3\Security\Authentication\Token\UsernamePassword)) {
			throw new \F3\FLOW3\Security\Exception\UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
		}

		$account = NULL;
		$credentials = $authenticationToken->getCredentials();

		if (is_array($credentials) && isset($credentials['username'])) {
			if ($this->ldapService->isServerOnline()) {
				$userDn = $this->ldapService->authenticate($credentials['username'], $credentials['password']);
				if ($userDn) {
					$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->name);
					if (empty($account)) {
						$account = new \F3\LDAP\Domain\Model\Account();
						$account->setDn($userDn);
						$account->setAccountIdentifier($credentials['username']);
						$account->setAuthenticationProviderName($this->name);
						$this->accountRepository->add($account);

							// @todo: create party for name
					}

					if (is_object($account)) {
							// Cache the password to have cached login if LDAP is unavailable
						$account->setCredentialsSource($this->hashService->generateSaltedMd5($credentials['password']));
						$authenticationToken->setAuthenticationStatus(\F3\FLOW3\Security\Authentication\TokenInterface::AUTHENTICATION_SUCCESSFUL);
						$authenticationToken->setAccount($account);
					} elseif ($authenticationToken->getAuthenticationStatus() !== \F3\FLOW3\Security\Authentication\TokenInterface::AUTHENTICATION_SUCCESSFUL) {
						$authenticationToken->setAuthenticationStatus(\F3\FLOW3\Security\Authentication\TokenInterface::NO_CREDENTIALS_GIVEN);
					}
				} else {
					$authenticationToken->setAuthenticationStatus(\F3\FLOW3\Security\Authentication\TokenInterface::WRONG_CREDENTIALS);
				}
			} else {
				$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $this->name);

				/**
				 * Server not available, fallback to the cached password hash
				 */
				if (is_object($account)) {
					if ($this->hashService->validateSaltedMd5($credentials['password'], $account->getCredentialsSource())) {
						$authenticationToken->setAuthenticationStatus(\F3\FLOW3\Security\Authentication\TokenInterface::AUTHENTICATION_SUCCESSFUL);
						$authenticationToken->setAccount($account);
					} else {
						$authenticationToken->setAuthenticationStatus(\F3\FLOW3\Security\Authentication\TokenInterface::WRONG_CREDENTIALS);
					}
				} elseif ($authenticationToken->getAuthenticationStatus() !== \F3\FLOW3\Security\Authentication\TokenInterface::AUTHENTICATION_SUCCESSFUL) {
					$authenticationToken->setAuthenticationStatus(\F3\FLOW3\Security\Authentication\TokenInterface::NO_CREDENTIALS_GIVEN);
				}

			}
		} else {
			$authenticationToken->setAuthenticationStatus(\F3\FLOW3\Security\Authentication\TokenInterface::NO_CREDENTIALS_GIVEN);
		}
	}
}

?>