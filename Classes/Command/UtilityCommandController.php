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

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;
use Neos\Flow\Mvc\Exception\StopActionException;
use Neos\Flow\Security\Exception\MissingConfigurationException;
use Neos\Ldap\Service\DirectoryService;
use Neos\Utility\Arrays;
use Neos\Utility\Files;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Command controller to test settings and query the directory
 */
class UtilityCommandController extends CommandController
{
    /**
     * @Flow\InjectConfiguration(path="security.authentication.providers", package="Neos.Flow")
     * @var mixed[][]
     */
    protected $authenticationProvidersConfiguration;

    /**
     * Simple bind command to test if a bind is possible at all
     *
     * @param string|null $username Username to be used while binding
     * @param string|null $password Password to be used while binding
     * @param string|null $providerName Name of the authentication provider to use
     * @param string|null $settingsFile Path to a yaml file containing the settings to use for testing purposes
     * @return void
     * @throws StopActionException
     */
    public function bindCommand(
        string $username = null,
        string $password = null,
        string $providerName = null,
        string $settingsFile = null
    ) {
        $options = $this->getOptions($providerName, $settingsFile);
        $bindDn = isset($options['bind']['dn'])
            ? sprintf($options['bind']['dn'], $username ?? '')
            : null
        ;
        $message = 'Attempt to bind ' . ($bindDn === null ? 'anonymously' : 'to ' . $bindDn);
        if ($password !== null) {
            $message .= ', using password,';
        }
        try {
            new DirectoryService($options, $username, $password);
            $this->outputLine($message . ' succeeded');
        } catch (ConnectionException $exception) {
            $this->outputLine($message . ' failed');
            $this->outputLine($exception->getMessage());
            $this->quit(1);
            // quit always throws StopActionException, so we cannot get here
            return;
        }
    }

    /**
     * Query the directory
     *
     * @param string $baseDn The base dn to search in
     * @param string $query The query to use, for example "(objectclass=*)"
     * @param string|null $providerName Name of the authentication provider to use
     * @param string|null $settingsFile Path to a yaml file containing the settings to use for testing purposes
     * @param string|null $displayColumns Comma separated list of columns to show, like "cn,objectclass"
     * @param string|null $username Username to be used to bind
     * @param string|null $password Password to be used to bind
     *
     * @return void
     * @throws StopActionException
     */
    public function queryCommand(
        string $baseDn,
        string $query,
        string $providerName = null,
        string $settingsFile = null,
        string $displayColumns = null,
        string $username = null,
        string $password = null
    ) {
        $options = $this->getOptions($providerName, $settingsFile);

        $this->outputLine('Base DN: %s', [$baseDn]);
        $this->outputLine('Query: %s', [$query]);

        $columns = $displayColumns === null ? null : Arrays::trimExplode(',', $displayColumns);

        try {
            $directoryService = new DirectoryService($options, $username, $password);
            $entries = $directoryService->query($baseDn, $query, $columns);
        } catch (MissingConfigurationException $exception) {
            // We check for baseDn above, so this will never be thrown
            /** @var Entry[] $entries */
        } catch (\RuntimeException $exception) {
        // line above can be replaced by the following line when we require PHP 7.1
        // } catch (ConnectionException | \Symfony\Component\Ldap\Exception\LdapException $exception) {
            $this->outputLine($exception->getMessage());
            $this->quit(1);
            // quit always throws StopActionException, so we cannot get here
            return;
        }
        $this->outputEntriesTable($entries);
    }

    /**
     * Load options by provider name or by a settings file (first has precedence)
     *
     * @param string|null $providerName Name of the authentication provider to use
     * @param string|null $settingsFile Path to a yaml file containing the settings to use for testing purposes
     * @return mixed[]
     * @throws StopActionException
     */
    protected function getOptions(string $providerName = null, string $settingsFile = null) : array
    {
        if ($providerName !== null) {
            if (isset($this->authenticationProvidersConfiguration[$providerName]['providerOptions'])
                && \is_array($this->authenticationProvidersConfiguration[$providerName]['providerOptions'])
            ) {
                return $this->authenticationProvidersConfiguration[$providerName]['providerOptions'];
            }
            $this->outputLine('No configuration found for given providerName');
            if ($settingsFile === null) {
                $this->quit(3);
                // quit always throws StopActionException, so we cannot get here
                return [];
            }
        }

        if ($settingsFile !== null) {
            if (!\file_exists($settingsFile)) {
                $this->outputLine('Could not find settings file on path %s', [$settingsFile]);
                $this->quit(1);
                // quit always throws StopActionException, so we cannot get here
                return [];
            }
            try {
                // Yaml::parseFile() introduced in symfony/yaml 3.4.0
                // When above is required, we can drop dependency on neos/utility-files
                $directoryServiceOptions = method_exists(Yaml::class, 'parseFile')
                    ? Yaml::parseFile($settingsFile)
                    : Yaml::parse(Files::getFileContents($settingsFile))
                ;
            } catch (ParseException $exception) {
                $this->outputLine($exception->getMessage());
                $this->quit(3);
                // quit always throws StopActionException, so we cannot get here
                return [];
            }
            if (!\is_array($directoryServiceOptions)) {
                $this->outputLine('No configuration found in given settingsFile');
                $this->quit(3);
                // quit always throws StopActionException, so we cannot get here
                return [];
            }
            return $directoryServiceOptions;
        }

        $this->outputLine(
            'Neither providerName nor settingsFile is passed as argument. You need to pass one of those.'
        );
        $this->quit(1);
        // quit always throws StopActionException, so we cannot get here
        return [];
    }

    /**
     * Outputs a table for given entries
     *
     * @param Entry[] $entries
     * @return void
     */
    protected function outputEntriesTable(array $entries)
    {
        $headers = ['dn'];
        $rows = [];

        $this->outputLine('%s results found', [\count($entries)]);

        foreach ($entries as $index => $entry) {
            $rows[$index] = ['dn' => $entry->getDn()];
            foreach ($entry->getAttributes() as $propertyName => $propertyValue) {
                if ($index === 0) {
                    $headers[] = $propertyName;
                }

                $rows[$index][$propertyName] = \is_array($propertyValue)
                    ? implode(', ', $propertyValue)
                    : $propertyValue
                ;
            }
        }

        $this->output->outputTable($rows, $headers);
    }
}
