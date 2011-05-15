<?php
declare(ENCODING = 'utf-8');
namespace F3\LDAP\Domain\Model;

/*                                                                        *
 * This script belongs to the FLOW3 package "LDAP".                       *
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

use \Doctrine\Common\Collections\ArrayCollection;

/**
 * An account model
 *
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License, version 2
 * @scope prototype
 * @entity
 */
class Account extends \F3\FLOW3\Security\Account {

	/**
	 * @var string
	 * @identity
	 */
	protected $dn;

	/**
	 * Set the distinguished name property
	 *
	 * @param string $dn
	 */
	public function setDn($dn) {
		$this->dn = $dn;
	}

	/**
	 * Get the distinguished name property
	 *
	 * @return string
	 */
	public function getDn() {
		return $this->dn;
	}

	/**
	 * Constructor
	 *
	 * @return void
	 */
	public function __construct() {
		parent::__construct();
	}

}

?>