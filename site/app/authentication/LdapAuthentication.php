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

        if (!@ldap_bind($ldap, $settings['service_dn'], $settings['service_pw'])) {
            return false;
        }

        $filter = str_replace('{uid}', $this->user_id, $settings['filter']);
        $result = ldap_search($ldap, $settings['base_dn'], $filter, [$settings['pwd_field']]);

        $entries = ldap_get_entries($ldap, $result);

        if ($entries['count'] === 0) {
            // User not found
            return false;
        }

        if (@ldap_bind($ldap, $entries[0]['dn'], $this->password)) {
            return true;
        } else {
            return false;
        }

        // We grab the user Password Hash
        // $attr = strtolower($settings['pwd_field']);
        // $user_passwd_hash = $entries[0][$attr][0];

        // And if it is the same as the user input we allow access
        // return crypt($this->password, $user_passwd_hash) === $user_passwd_hash;

        // fixme_ldap
        // this does not work for us
        //return @ldap_bind($ldap, $user_dn, $this->password);
    }
}
