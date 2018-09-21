<?php
namespace Neos\Ldap\Command;

/*
 * This file is part of the Neos.Ldap package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Symfony\Component\Yaml\Yaml;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;
use Neos\Utility\Arrays;
use Neos\Utility\Files;
use Neos\Ldap\Service\DirectoryService;

/**
 * Command controller to test settings and query the directory
 */
class UtilityCommandController extends CommandController
{
    /**
     * @Flow\InjectConfiguration(path="security.authentication.providers", package="Neos.Flow")
     * @var array
     */
    protected $authenticationProvidersConfiguration;

    /**
     * @var array
     */
    protected $options;

    /**
     * Try authenticating a user using a DirectoryService that's connected to a directory
     *
     * @param string $username The username to authenticate
     * @param string $password The password to use while authenticating
     * @param string $providerName Name of the authentication provider to use
     * @param string $settingsFile Path to a yaml file containing the settings to use for testing purposes
     *
     * @return void
     */
    public function authenticateCommand($username, $password, $providerName = null, $settingsFile = null)
    {
        $directoryService = $this->getDirectoryService($providerName, $settingsFile);

        try {
            $directoryService->authenticate($username, $password);
            $this->outputLine('Successfully authenticated %s with given password', [$username]);
        } catch (\Exception $exception) {
            $this->outputLine($exception->getMessage());
            $this->quit(1);
        }
    }

    /**
     * Simple bind command to test if a bind is possible at all
     *
     * @param string $username Username to be used while binding
     * @param string $password Password to be used while binding
     * @param string $providerName Name of the authentication provider to use
     * @param string $settingsFile Path to a yaml file containing the settings to use for testing purposes
     * @return void
     */
    public function bindCommand($username = null, $password = null, $providerName = null, $settingsFile = null)
    {
        $directoryService = $this->getDirectoryService($providerName, $settingsFile);

        try {
            if ($username === null && $password === null) {
                $result = ldap_bind($directoryService->getConnection());
                $this->outputLine('Anonymous bind attempt %s', [$result === false ? 'failed' : 'succeeded']);
                if ($result === false) {
                    $this->quit(1);
                }
            } else {
                $directoryService->bind($username, $password);
                $this->outputLine('Bind successful with user %s, using password is %s', [$username, $password === null ? 'NO' : 'YES']);
            }
        } catch (\Exception $exception) {
            $this->outputLine('Failed to bind with username %s, using password is %s', [$username, $password === null ? 'NO' : 'YES']);
            $this->outputLine($exception->getMessage());
            $this->quit(1);
        }
    }

    /**
     * Query the directory
     *
     * @param string $query The query to use, for example (objectclass=*)
     * @param string $baseDn The base dn to search in
     * @param string $providerName Name of the authentication provider to use
     * @param string $settingsFile Path to a yaml file containing the settings to use for testing purposes
     * @param string $displayColumns Comma separated list of columns to show, like: dn,objectclass
     * @return void
     */
    public function queryCommand(
        $query,
        $baseDn = null,
        $providerName = null,
        $settingsFile = null,
        $displayColumns = 'dn'
    ) {
        $directoryService = $this->getDirectoryService($providerName, $settingsFile);

        if ($baseDn === null) {
            $baseDn = Arrays::getValueByPath($this->options, 'baseDn');
        }

        $this->outputLine('Query: %s', [$query]);
        $this->outputLine('Base DN: %s', [$baseDn]);

        $searchResult = @ldap_search(
            $directoryService->getConnection(),
            $baseDn,
            $query
        );

        if ($searchResult === false) {
            $this->outputLine(ldap_error($directoryService->getConnection()));
            $this->quit(1);
        }

        $this->outputLdapSearchResultTable($directoryService->getConnection(), $searchResult, $displayColumns);
    }

    /**
     * @param string $providerName Name of the authentication provider to use
     * @param string $settingsFile Path to a yaml file containing the settings to use for testing purposes
     * @return DirectoryService
     * @throws \Neos\Flow\Mvc\Exception\StopActionException
     */
    protected function getDirectoryService($providerName, $settingsFile)
    {
        $directoryServiceOptions = $this->getOptions($providerName, $settingsFile);
        if (!is_array($directoryServiceOptions)) {
            $this->outputLine('No configuration found for given providerName / settingsFile');
            $this->quit(3);
        }

        return new DirectoryService('cli', $directoryServiceOptions);
    }

    /**
     * Load options by provider name or by a settings file (first has precedence)
     *
     * @param string $providerName Name of the authentication provider to use
     * @param string $settingsFile Path to a yaml file containing the settings to use for testing purposes
     * @return array|mixed
     * @throws \Neos\Flow\Mvc\Exception\StopActionException
     */
    protected function getOptions($providerName = null, $settingsFile = null)
    {
        if ($providerName !== null && array_key_exists($providerName, $this->authenticationProvidersConfiguration)) {
            $this->options = $this->authenticationProvidersConfiguration[$providerName]['providerOptions'];
            return $this->options;
        }

        if ($settingsFile !== null) {
            if (!file_exists($settingsFile)) {
                $this->outputLine('Could not find settings file on path %s', [$settingsFile]);
                $this->quit(1);
            }
            $this->options = Yaml::parse(Files::getFileContents($settingsFile));
            return $this->options;
        }

        $this->outputLine('Neither providerName or settingsFile is passed as argument. You need to pass one of those.');
        $this->quit(1);
    }

    /**
     * Outputs a table for given search result
     *
     * @param resource $connection
     * @param resource $searchResult
     * @param $displayColumns
     * @return void
     */
    protected function outputLdapSearchResultTable($connection, $searchResult, $displayColumns)
    {
        $headers = [];
        $rows = [];

        $displayColumns = Arrays::trimExplode(',', $displayColumns);

        $entries = ldap_get_entries($connection, $searchResult);
        $this->outputLine('%s results found', [$entries['count']]);

        foreach ($entries as $index => $ldapSearchResult) {
            if ($index === 'count') {
                continue;
            }

            if ($headers === []) {
                foreach ($ldapSearchResult as $propertyName => $propertyValue) {
                    if (is_integer($propertyName)) {
                        continue;
                    }
                    if ($displayColumns === null || in_array($propertyName, $displayColumns)) {
                        $headers[] = $propertyName;
                    }
                }
            }

            $row = [];
            foreach ($ldapSearchResult as $propertyName => $propertyValue) {
                if (is_integer($propertyName)) {
                    continue;
                }
                if ($displayColumns !== null && !in_array($propertyName, $displayColumns)) {
                    continue;
                }

                if (isset($propertyValue['count'])) {
                    unset($propertyValue['count']);
                }

                if (is_array($propertyValue)) {
                    $row[$propertyName] = implode(", ", $propertyValue);
                } else {
                    $row[$propertyName] = $propertyValue;
                }
            }
            $rows[] = $row;
        }

        $this->output->outputTable($rows, $headers);
    }
}
