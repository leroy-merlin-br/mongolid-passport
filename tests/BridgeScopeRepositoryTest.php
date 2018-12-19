<?php

use Laravel\Passport\Passport;
use PHPUnit\Framework\TestCase;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\ScopeRepository;

class BridgeScopeRepositoryTest extends TestCase
{
    public function test_invalid_scopes_are_removed()
    {
        Passport::tokensCan([
            'scope-1' => 'description',
        ]);

        $repository = new ScopeRepository;

        $scopes = $repository->finalizeScopes(
            [$scope1 = new Scope('scope-1'), new Scope('scope-2')], 'client_credentials', new Client('id', 'name', 'http://localhost', '*'), 1
        );

        $this->assertEquals([$scope1], $scopes);
    }

    public function test_superuser_scope_cant_be_applied_if_wrong_grant()
    {
        Passport::tokensCan([
            'scope-1' => 'description',
        ]);

        $repository = new ScopeRepository;

        $scopes = $repository->finalizeScopes(
            [$scope1 = new Scope('*')], 'client_credentials', new Client('id', 'name', 'http://localhost', '*'), 1
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
            $rawScopes, 'client_credentials', new Client('id', 'name', 'http://localhost', 'scope-1,scope-2'), 1
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
            $rawScopes, 'client_credentials', new Client('id', 'name', 'http://localhost', '*'), 1
        );

        $this->assertEquals($rawScopes, $scopes);
    }

    /**
     * @expectedException League\OAuth2\Server\Exception\OAuthServerException
     */
    public function test_validate_client_allowed_scopes_should_throw_exception()
    {
        Passport::tokensCan([
            'scope-1' => 'description',
        ]);

        $repository = new ScopeRepository;

        $scopes = $repository->finalizeScopes(
            [new Scope('scope-1')], 'client_credentials', new Client('id', 'name', 'http://localhost', 'scope-2,scope-3'), 1
        );
    }

    /**
     * @expectedException League\OAuth2\Server\Exception\OAuthServerException
     */
    public function test_validate_client_allowed_scopes_should_throw_exception_for_a_client_with_no_allowed_scope()
    {
        Passport::tokensCan([
            'scope-1' => 'description',
        ]);

        $repository = new ScopeRepository;

        $scopes = $repository->finalizeScopes(
            [new Scope('scope-1')], 'client_credentials', new Client('id', 'name', 'http://localhost'), 1
        );
    }
}
