<?php

namespace App\Service;

use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\Adapter\ExtLdap\Connection as ExtLdapConnection;

class LdapService
{
    private const ACCOUNT_DISABLED_FLAG = 0x2;

    private Ldap $ldap;
    private ExtLdapConnection $extConnection;
    private string $baseDn;

    public function __construct(
        string $host,
        int $port,
        string $baseDn,
        string $userDn,
        string $password,
        ?string $encryption = null,
        bool $ignoreCert = false
    ) {
        $this->baseDn = $baseDn;

        $encryption ??= str_starts_with($host, 'ldaps://') ? 'ssl' : 'none';
        $host = preg_replace('#^ldaps?://#', '', $host);

        if ($ignoreCert) {
            putenv('LDAPTLS_REQCERT=never');
        }

        $this->ldap = Ldap::create('ext_ldap', [
            'host' => $host,
            'port' => $port,
            'encryption' => $encryption,
        ]);

        $this->ldap->bind($userDn, $password);

        $this->extConnection = $this->getExtConnectionFromLdap($this->ldap);
    }

    private function getExtConnectionFromLdap(Ldap $ldap): ExtLdapConnection
    {
        $refLdap = new \ReflectionObject($ldap);
        $adapterProp = $refLdap->getProperty('adapter');
        $adapterProp->setAccessible(true);
        $adapter = $adapterProp->getValue($ldap);

        $refAdapter = new \ReflectionObject($adapter);
        $connProp = $refAdapter->getProperty('connection');
        $connProp->setAccessible(true);

        return $connProp->getValue($adapter);
    }

    public function findUser(?string $samAccountName, ?string $email): ?array
    {
        if (!$samAccountName && !$email) {
            return null;
        }

        $filter = $samAccountName
            ? $this->buildEqualityFilter('sAMAccountName', $samAccountName)
            : $this->buildEqualityFilter('mail', (string) $email);

        $entry = $this->queryFirstEntry($this->baseDn, $filter, ['scope' => 'sub']);

        if (!$entry instanceof Entry) {
            return null;
        }

        $lockoutTime = $entry->getAttribute('lockoutTime')[0] ?? null;
        $uac = $entry->getAttribute('userAccountControl')[0] ?? null;
        $lastLogonRaw = $entry->getAttribute('lastLogonTimestamp')[0] ?? null;

        $isLocked = isset($lockoutTime) && $lockoutTime !== '0';

        $isDisabled = false;
        if ($uac !== null) {
            $isDisabled = ((int) $uac & self::ACCOUNT_DISABLED_FLAG) === self::ACCOUNT_DISABLED_FLAG;
        }

        $lastLogon = null;
        if ($lastLogonRaw && is_numeric($lastLogonRaw)) {
            $windowsTimestamp = (int) $lastLogonRaw;
            $lastLogonUnix = (int) ($windowsTimestamp / 10000000 - 11644473600);
            $lastLogon = (new \DateTime())->setTimestamp($lastLogonUnix)->format('Y-m-d H:i:s');
        }

        return [
            'dn' => $entry->getDn(),
            'cn' => $entry->getAttribute('cn')[0] ?? null,
            'mail' => $entry->getAttribute('mail')[0] ?? null,
            'sAMAccountName' => $entry->getAttribute('sAMAccountName')[0] ?? null,
            'memberOf' => array_map($this->extractCommonName(...), $entry->getAttribute('memberOf') ?? []),
            'isLocked' => $isLocked,
            'isDisabled' => $isDisabled,
            'lastLogon' => $lastLogon,
            'position' => $entry->getAttribute('title')[0] ?? null,
            'department' => $entry->getAttribute('department')[0] ?? null,
            'description' => $entry->getAttribute('description')[0] ?? null
        ];
    }

    public function getDnBySamAccountName(string $samAccountName): ?string
    {
        $entry = $this->queryFirstEntry(
            $this->baseDn,
            $this->buildEqualityFilter('sAMAccountName', $samAccountName),
            ['scope' => 'sub']
        );

        return $entry?->getDn();
    }

    public function unlockUserByDn(string $dn): void
    {
        $this->modifyBatch($dn, [
            [
                'attrib' => 'lockoutTime',
                'modtype' => LDAP_MODIFY_BATCH_REPLACE,
                'values' => ['0'],
            ],
        ], 'Unlock fehlgeschlagen');
    }

    public function disableUserByDn(string $dn): void
    {
        $entry = $this->getEntryByDn($dn);
        if (!$entry instanceof Entry) {
            throw new \RuntimeException("Benutzer nicht gefunden: $dn");
        }

        $currentValue = $entry->getAttribute('userAccountControl')[0] ?? null;

        if ($currentValue === null) {
            throw new \RuntimeException("userAccountControl nicht vorhanden.");
        }

        $newValue = (int) $currentValue | self::ACCOUNT_DISABLED_FLAG;

        $this->modifyBatch($dn, [
            [
                'attrib' => 'userAccountControl',
                'modtype' => LDAP_MODIFY_BATCH_REPLACE,
                'values' => [$newValue],
            ],
        ], 'Deaktivierung fehlgeschlagen');
    }

    public function enableUserByDn(string $dn): void
    {
        $entry = $this->getEntryByDn($dn);
        if (!$entry instanceof Entry) {
            throw new \RuntimeException("Benutzer nicht gefunden: $dn");
        }

        $currentValue = $entry->getAttribute('userAccountControl')[0] ?? null;

        if ($currentValue === null) {
            throw new \RuntimeException("userAccountControl nicht vorhanden.");
        }

        $newValue = (int) $currentValue & ~self::ACCOUNT_DISABLED_FLAG;

        $this->modifyBatch($dn, [
            [
                'attrib' => 'userAccountControl',
                'modtype' => LDAP_MODIFY_BATCH_REPLACE,
                'values' => [$newValue],
            ],
        ], 'Aktivierung fehlgeschlagen');
    }

    public function resetPasswordByDn(string $dn, string $newPassword): void
    {
        $encoded = mb_convert_encoding('"' . $newPassword . '"', 'UTF-16LE');

        $this->modifyBatch($dn, [
            [
                'attrib' => 'unicodePwd',
                'modtype' => LDAP_MODIFY_BATCH_REPLACE,
                'values' => [$encoded],
            ],
        ], 'Passwortänderung fehlgeschlagen');
    }

    public function getAllGroups(): array
    {
        $query = $this->ldap->query($this->baseDn, '(&(objectCategory=group))', [
            'scope' => 'sub'
        ]);

        $results = $query->execute();

        return array_map(fn($entry) => [
            'cn' => $entry->getAttribute('cn')[0] ?? null,
            'dn' => $entry->getDn(),
        ], iterator_to_array($results));
    }

    public function getGroupMembersByCn(string $cn): array
    {
        $groupDn = $this->resolveGroupDnByCn($cn);
        if (!$groupDn) {
            throw new \RuntimeException("Gruppe nicht gefunden");
        }

        $query = $this->ldap->query($groupDn, '(objectClass=*)');
        $results = $query->execute();

        if (count($results) === 0) {
            throw new \RuntimeException("Gruppe nicht gefunden");
        }

        $entry = $results[0];
        $members = $entry->getAttribute('member') ?? [];

        $userInfos = [];
        foreach ($members as $memberDn) {
            try {
                $userEntry = $this->getEntryByDn($memberDn);
                if ($userEntry instanceof Entry) {
                    $userInfos[] = $this->mapUserSummary($memberDn, $userEntry);
                }
            } catch (\Throwable $t) {
                continue;
            }
        }

        return $userInfos;
    }

    public function addUserToGroup(string $samAccountName, string $groupDn): void
    {
        $userDn = $this->getDnBySamAccountName($samAccountName);
        if (!$userDn) {
            throw new \RuntimeException("Benutzer nicht gefunden");
        }

        $this->modifyBatch($groupDn, [[
            'attrib' => 'member',
            'modtype' => LDAP_MODIFY_BATCH_ADD,
            'values' => [$userDn],
        ]], 'Fehler beim Hinzufügen');
    }

    public function removeUserFromGroup(string $samAccountName, string $groupDn): void
    {
        $userDn = $this->getDnBySamAccountName($samAccountName);
        if (!$userDn) {
            throw new \RuntimeException("Benutzer nicht gefunden");
        }

        $this->modifyBatch($groupDn, [[
            'attrib' => 'member',
            'modtype' => LDAP_MODIFY_BATCH_REMOVE,
            'values' => [$userDn],
        ]], 'Fehler beim Entfernen');
    }

    public function resolveGroupDnByCn(string $cn): ?string
    {
        $entry = $this->queryFirstEntry(
            $this->baseDn,
            '(&(objectCategory=group)' . $this->buildEqualityFilter('cn', $cn) . ')',
            ['scope' => 'sub']
        );

        return $entry?->getDn();
    }

    private function buildEqualityFilter(string $attribute, string $value): string
    {
        return sprintf('(%s=%s)', $attribute, ldap_escape($value, '', LDAP_ESCAPE_FILTER));
    }

    private function queryFirstEntry(string $dn, string $filter, array $options = []): ?Entry
    {
        $results = $this->ldap->query($dn, $filter, $options)->execute();

        return count($results) > 0 ? $results[0] : null;
    }

    private function getEntryByDn(string $dn): ?Entry
    {
        return $this->queryFirstEntry($dn, '(objectClass=*)');
    }

    private function modifyBatch(string $dn, array $modifications, string $errorPrefix): void
    {
        $ldapResource = $this->extConnection->getResource();

        if (!@ldap_modify_batch($ldapResource, $dn, $modifications)) {
            $error = ldap_error($ldapResource);
            throw new \RuntimeException("$errorPrefix: $error");
        }
    }

    private function extractCommonName(string $dn): string
    {
        if (preg_match('/CN=([^,]+)/i', $dn, $matches)) {
            return $matches[1];
        }

        return $dn;
    }

    private function mapUserSummary(string $dn, Entry $entry): array
    {
        return [
            'dn' => $dn,
            'cn' => $entry->getAttribute('cn')[0] ?? null,
            'mail' => $entry->getAttribute('mail')[0] ?? null,
            'sAMAccountName' => $entry->getAttribute('sAMAccountName')[0] ?? null,
        ];
    }

}
