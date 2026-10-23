<?php

declare(strict_types=1);

namespace app\authentication;

class LdapAuthentication extends AbstractAuthentication {
    public function authenticate() {
        if (empty($this->user_id) || empty($this->password) || $this->core->getQueries()->getSubmittyUser($this->user_id) === null) {
            return false;
        }

        $settings = $this->core->getConfig()->getLdapOptions();

        $ldap = ldap_connect($settings['url']);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

        // Bind as the service account to look up the DN of the user
        if (!@ldap_bind($ldap, $settings['service_dn'], $settings['service_pw'])) {
            return false;
        }

        $filter = str_replace('{uid}', ldap_escape($this->user_id, '', LDAP_ESCAPE_FILTER), $settings['filter']);
        $result = @ldap_search($ldap, $settings['base_dn'], $filter, [$settings['pwd_field']]);
        if ($result === false) {
            return false;
        }

        $entries = ldap_get_entries($ldap, $result);
        if ($entries['count'] === 0) {
            return false;
        }

        // Verify the password by binding as the user
        return @ldap_bind($ldap, $entries[0]['dn'], $this->password);
    }
}
