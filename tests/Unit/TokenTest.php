<?php

namespace Laravel\Passport\Tests\Unit;

use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use PHPUnit\Framework\TestCase;
use ReflectionObject;

class TokenTest extends TestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();

        Passport::$withInheritedScopes = false;
        Passport::useRefreshTokenModel(\Laravel\Passport\RefreshToken::class);
    }

    public function test_token_can_determine_if_it_has_scopes()
    {
        Passport::$withInheritedScopes = false;

        $token = new Token();
        $token->fill(['scopes' => ['user']]);

        $this->assertTrue($token->can('user'));
        $this->assertFalse($token->can('something'));
        $this->assertTrue($token->cant('something'));
        $this->assertFalse($token->cant('user'));

        $this->assertTrue($token->cant('user:read'));

        $token = new Token();
        $token->fill(['scopes' => ['*']]);
        $this->assertTrue($token->can('user'));
        $this->assertTrue($token->can('something'));
    }

    public function test_token_can_determine_if_it_has_inherited_scopes()
    {
        Passport::$withInheritedScopes = true;

        $token = new Token();
        $token->fill([
            'scopes' => [
                'user',
                'group',
                'admin:webhooks:read',
            ],
        ]);

        $this->assertTrue($token->can('user'));
        $this->assertTrue($token->can('group'));
        $this->assertTrue($token->can('user:read'));
        $this->assertTrue($token->can('group:read'));
        $this->assertTrue($token->can('admin:webhooks:read'));

        $this->assertTrue($token->cant('admin:webhooks'));

        $this->assertFalse($token->can('something'));

        $token = new Token();
        $token->fill(['scopes' => ['*']]);
        $this->assertTrue($token->can('user'));
        $this->assertTrue($token->can('something'));
        $this->assertTrue($token->can('admin:webhooks:write'));
    }

    public function test_token_resolves_inherited_scopes()
    {
        $token = new Token;

        $reflector = new ReflectionObject($token);
        $method = $reflector->getMethod('resolveInheritedScopes');
        $method->setAccessible(true);
        $inheritedScopes = $method->invoke($token, 'admin:webhooks:read');

        $this->assertSame([
            'admin',
            'admin:webhooks',
            'admin:webhooks:read',
        ], $inheritedScopes);
    }

    public function test_token_can_resolve_its_refresh_token()
    {
        Passport::useRefreshTokenModel(RefreshTokenModelStub::class);

        RefreshTokenModelStub::$lastQuery = null;

        $token = new Token();
        $token->_id = 'access-token-id';

        $refreshToken = $token->refreshToken();

        $this->assertSame(['access_token_id' => 'access-token-id'], RefreshTokenModelStub::$lastQuery);
        $this->assertInstanceOf(RefreshTokenRecordStub::class, $refreshToken);
    }
}

class RefreshTokenModelStub
{
    public static $lastQuery;

    public static function first($query)
    {
        static::$lastQuery = $query;

        return new RefreshTokenRecordStub;
    }
}

class RefreshTokenRecordStub
{
}
