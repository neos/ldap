For this Package to work you have to add some annotations to the F3\FLOW3\Security\Account class.

The annotations should look like:

/**
 * An account model
 *
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License, version 2
 * @scope prototype
 * @entity
 * @InheritanceType("SINGLE_TABLE")
 * @DiscriminatorColumn(name="discr", type="string")
 * @DiscriminatorMap({"F3\FLOW3\Security\Account" = "F3\FLOW3\Security\Account", "F3\LDAP\Domain\Model\Account" = "F3\LDAP\Domain\Model\Account"})
 */
class Account {