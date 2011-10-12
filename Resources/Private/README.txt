For this Package to work you have to add some annotations to the TYPO3\FLOW3\Security\Account class.

The annotations should look like:

/**
 * An account model
 *
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License, version 2
 * @scope prototype
 * @entity
 * @InheritanceType("SINGLE_TABLE")
 * @DiscriminatorColumn(name="discr", type="string")
 * @DiscriminatorMap({"TYPO3\FLOW3\Security\Account" = "TYPO3\FLOW3\Security\Account", "TYPO3\LDAP\Domain\Model\Account" = "TYPO3\LDAP\Domain\Model\Account"})
 */
class Account {