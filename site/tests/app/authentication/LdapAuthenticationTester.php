<?php

declare(strict_types=1);

namespace tests\app\authentication;

use app\authentication\LdapAuthentication;
use app\libraries\Core;
use app\libraries\database\DatabaseQueries;
use app\models\Config;
use app\models\User;
use PHPUnit\Framework\TestCase;

class LdapAuthenticationTester extends TestCase {
    use \phpmock\phpunit\PHPMock;

    public function testEmptyUserId() {
        $core = new Core();
        $auth = new LdapAuthentication($core);
        $auth->setUserId('');
        $auth->setPassword('');
        $this->assertFalse($auth->authenticate());
    }

    public function testEmptyPassword() {
        $core = new Core();
        $auth = new LdapAuthentication($core);
        $auth->setUserId('instructor');
        $auth->setPassword('');
        $this->assertFalse($auth->authenticate());
    }

    public function testInvalidUser() {
        $core = new Core();
        $queries = $this->createMock(DatabaseQueries::class);
        $queries->expects($this->once())->method('getSubmittyUser')->with('instructor')->willReturn(null);
        $core->setQueries($queries);
        $auth = new LdapAuthentication($core);
        $auth->setUserId('instructor');
        $auth->setPassword('instructor');
        $this->assertFalse($auth->authenticate());
    }

    private function createAuth(string $user_id = 'instructor'): LdapAuthentication {
        $core = new Core();
        $queries = $this->createMock(DatabaseQueries::class);
        $user = new User($core, [
            'user_id' => 'test',
            'user_givenname' => 'Test',
            'user_familyname' => 'Person',
            'user_pronouns' => '',
            'display_pronouns' => false,
            'user_email' => '',
            'user_email_secondary' => '',
            'user_email_secondary_notify' => false
        ]);
        $queries->expects($this->once())->method('getSubmittyUser')->with($user_id)->willReturn($user);
        $core->setQueries($queries);
        $config = new Config($core);
        $config->setLdapOptions([
            'url' => 'ldap://localhost',
            'service_dn' => 'uid=service,ou=users,dc=vagrant,dc=local',
            'service_pw' => 'service_password',
            'pwd_field' => 'userPassword',
            'base_dn' => 'ou=users,dc=vagrant,dc=local',
            'filter' => '(uid={uid})'
        ]);
        $core->setConfig($config);

        $auth = new LdapAuthentication($core);
        $auth->setUserId($user_id);
        $auth->setPassword('instructor');
        return $auth;
    }

    public function testPassLdap() {
        $auth = $this->createAuth();

        $ldap_bind = $this->getFunctionMock("app\\authentication", "ldap_bind");
        $binds = [];
        $ldap_bind
            ->expects($this->exactly(2))
            ->willReturnCallback(function ($ldap, $dn, $password) use (&$binds) {
                $binds[] = [$dn, $password];
                return true;
            });
        $ldap_search = $this->getFunctionMock("app\\authentication", "ldap_search");
        $ldap_search
            ->expects($this->once())
            ->with($this->anything(), 'ou=users,dc=vagrant,dc=local', '(uid=instructor)', ['userPassword'])
            ->willReturn(true);
        $ldap_get_entries = $this->getFunctionMock("app\\authentication", "ldap_get_entries");
        $ldap_get_entries
            ->expects($this->once())
            ->willReturn(['count' => 1, 0 => ['dn' => 'uid=instructor,ou=users,dc=vagrant,dc=local']]);

        $this->assertTrue($auth->authenticate());
        $this->assertSame([
            ['uid=service,ou=users,dc=vagrant,dc=local', 'service_password'],
            ['uid=instructor,ou=users,dc=vagrant,dc=local', 'instructor']
        ], $binds);
    }

    public function testFailLdap() {
        $auth = $this->createAuth();

        $ldap_bind = $this->getFunctionMock("app\\authentication", "ldap_bind");
        $ldap_bind
            ->expects($this->exactly(2))
            ->willReturnOnConsecutiveCalls(true, false);
        $ldap_search = $this->getFunctionMock("app\\authentication", "ldap_search");
        $ldap_search->expects($this->once())->willReturn(true);
        $ldap_get_entries = $this->getFunctionMock("app\\authentication", "ldap_get_entries");
        $ldap_get_entries
            ->expects($this->once())
            ->willReturn(['count' => 1, 0 => ['dn' => 'uid=instructor,ou=users,dc=vagrant,dc=local']]);

        $this->assertFalse($auth->authenticate());
    }

    public function testFailServiceBind() {
        $auth = $this->createAuth();

        $ldap_bind = $this->getFunctionMock("app\\authentication", "ldap_bind");
        $ldap_bind->expects($this->once())->willReturn(false);
        $ldap_search = $this->getFunctionMock("app\\authentication", "ldap_search");
        $ldap_search->expects($this->never());

        $this->assertFalse($auth->authenticate());
    }

    public function testUserNotInLdap() {
        $auth = $this->createAuth();

        $ldap_bind = $this->getFunctionMock("app\\authentication", "ldap_bind");
        $ldap_bind->expects($this->once())->willReturn(true);
        $ldap_search = $this->getFunctionMock("app\\authentication", "ldap_search");
        $ldap_search->expects($this->once())->willReturn(true);
        $ldap_get_entries = $this->getFunctionMock("app\\authentication", "ldap_get_entries");
        $ldap_get_entries->expects($this->once())->willReturn(['count' => 0]);

        $this->assertFalse($auth->authenticate());
    }

    public function testFailLdapSearch() {
        $auth = $this->createAuth();

        $ldap_bind = $this->getFunctionMock("app\\authentication", "ldap_bind");
        $ldap_bind->expects($this->once())->willReturn(true);
        $ldap_search = $this->getFunctionMock("app\\authentication", "ldap_search");
        $ldap_search->expects($this->once())->willReturn(false);
        $ldap_get_entries = $this->getFunctionMock("app\\authentication", "ldap_get_entries");
        $ldap_get_entries->expects($this->never());

        $this->assertFalse($auth->authenticate());
    }

    public function testFilterEscapesUserId() {
        $auth = $this->createAuth('a*)(uid=b');

        $ldap_bind = $this->getFunctionMock("app\\authentication", "ldap_bind");
        $ldap_bind->expects($this->once())->willReturn(true);
        $ldap_search = $this->getFunctionMock("app\\authentication", "ldap_search");
        $ldap_search
            ->expects($this->once())
            ->with($this->anything(), $this->anything(), '(uid=a\\2a\\29\\28uid=b)', $this->anything())
            ->willReturn(false);

        $this->assertFalse($auth->authenticate());
    }
}
