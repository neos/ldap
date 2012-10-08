<?php
namespace TYPO3\LDAP\Service\BindProvider;

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

/**
 * Bind to an OpenLDAP Server
 *
 * @Flow\Scope("prototype")
 */
abstract class AbstractBindProvider implements \TYPO3\LDAP\Service\BindProvider\BindProviderInterface {
	/**
	 * @var resource
	 */
	protected $linkIdentifier;

	/**
	 * @var array
	 */
	protected $options;

	/**
	 * @param resource $linkIdentifier
	 * @param array $options
	 */
	public function __construct($linkIdentifier, array $options) {
		$this->linkIdentifier = $linkIdentifier;
		$this->options = $options;
	}

	/**
	 * @return resource
	 */
	public function getLinkIdentifier() {
		return $this->linkIdentifier;
	}

	/**
	 * Return the filtered username for directory search
	 * overwrite for special needs
	 *
	 * @param string $username
	 * @return string
	 */
	public function getFilteredUsername($username) {
		return $username;
	}

}

?>