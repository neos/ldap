<?php
declare(ENCODING = 'utf-8');
namespace F3\LDAP\Service;

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

/**
 * A simple LDAP authentication service
 *
 * @throws \F3\FLOW3\Error\Exception
 */
class LDAP {

	/**
	 * @var array
	 */
	protected $options;

	/**
	 * @throws \F3\FLOW3\Error\Exception
	 * @param array $options
	 * @return void
	 * @author Rens Admiraal <rens.admiraal@typo3.org>
	 */
	public function __construct(array $options) {
		$this->options = $options;
		if (!function_exists('ldap_connect')) {
			throw new \F3\FLOW3\Error\Exception('PHP is not compiled with LDAP support', 1305406047);
		}
	}

	/**
	 * Authenticate a username / password against the LDAP server
	 *
	 * @param string $username
	 * @param string $password
	 * @return bool
	 */
	public function authenticate($username, $password) {
		try {
			$ldapConnection = ldap_connect($this->options['host'],$this->options['port']);
			$searchResult = ldap_search (
				$ldapConnection,
				$this->options['baseDn'],
				str_replace('?', $username, $this->options['filter'])
			);
			if ($searchResult) {
				$entries = ldap_get_entries($ldapConnection, $searchResult);
				if ($entries[0]) {
					// @todo: make LDAP options configurable
					ldap_set_option($ldapConnection,LDAP_OPT_PROTOCOL_VERSION,3);
					$res = ldap_bind(
						$ldapConnection,
						$entries[0][$this->options['attributes']['dn']],
						$password
					);
					if ($res) {
						return $entries[0][$this->options['attributes']['dn']];
					}
				}
			}
		} catch (\F3\FLOW3\Error\Exception $exception) {
			return FALSE;
		}
		return FALSE;
	}

	/**
	 * Check if the server is online / can be reached
	 * @todo: make a fancy version of this method
	 *
	 * @return bool
	 */
	public function isServerOnline() {
		try {
			fsockopen(
				$this->options['host'],
				$this->options['port'],
				$errorNumber,
				$errorString,
				2
			);
			return TRUE;
		} catch (\F3\FLOW3\Error\Exception $exception) {
			return FALSE;
		}
	}
}

?>