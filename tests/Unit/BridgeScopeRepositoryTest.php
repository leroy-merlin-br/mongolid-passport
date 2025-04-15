<?php

namespace Laravel\Passport\Tests\Unit;

use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Bridge\ScopeRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\TestCase;

class BridgeScopeRepositoryTest extends TestCase
{
    protected function tearDown(): void
    {
        Passport::$withInheritedScopes = false;
    }

    public function test_superuser_scope_cant_be_applied_if_wrong_grant_without_a_client_repository()
    {
        Passport::tokensCan([
            'scope-1' => 'description',
        ]);

        $repository = new ScopeRepository();

        $scopes = $repository->finalizeScopes(
            [$scope1 = new Scope('*')], 'refresh_token', new Client('id', 'name', 'http://localhost', false, null, '*'), 1
        );

        $this->assertEquals([], $scopes);
    }

    public function test_validate_client_allowed_scopes()
    {
        Passport::tokensCan([
            'scope-1' => 'description',
            'scope-2' => 'description',
        ]);

        $repository = new ScopeRepository;

        $rawScopes = [new Scope('scope-1'), new Scope('scope-2')];

        $scopes = $repository->finalizeScopes(
            $rawScopes, 'client_credentials', new Client('id', 'name', 'http://localhost', false, null, 'scope-1,scope-2'), 1
        );

        $this->assertEquals($rawScopes, $scopes);
    }

    public function test_validate_client_allowed_scopes_for_a_client_with_no_scope_restriction()
    {
        Passport::tokensCan([
            'scope-1' => 'description',
            'scope-2' => 'description',
        ]);

        $repository = new ScopeRepository;

        $rawScopes = [new Scope('scope-1'), new Scope('scope-2')];

        $scopes = $repository->finalizeScopes(
            $rawScopes, 'client_credentials', new Client('id', 'name', 'http://localhost', false, null, '*'), 1
        );

        $this->assertEquals($rawScopes, $scopes);
    }

    public function test_validate_client_allowed_scopes_should_throw_exception()
    {
        $this->expectException(OAuthServerException::class);
        Passport::tokensCan([
            'scope-1' => 'description',
        ]);

        $repository = new ScopeRepository;

        $scopes = $repository->finalizeScopes(
            [new Scope('scope-1')], 'client_credentials', new Client('id', 'name', 'http://localhost', false, null, 'scope-2,scope-3'), 1
        );
    }

    public function test_validate_client_allowed_scopes_should_throw_exception_for_a_client_with_no_allowed_scope()
    {
        $this->expectException(OAuthServerException::class);
        Passport::tokensCan([
            'scope-1' => 'description',
        ]);

        $repository = new ScopeRepository;

        $scopes = $repository->finalizeScopes(
            [new Scope('scope-1')], 'client_credentials', new Client('id', 'name', 'http://localhost'), 1
        );
    }
}
