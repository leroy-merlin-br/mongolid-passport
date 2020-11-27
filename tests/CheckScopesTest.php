<?php

use Illuminate\Auth\AuthenticationException;
use Laravel\Passport\Exceptions\MissingScopeException;
use PHPUnit\Framework\TestCase;
use Laravel\Passport\Http\Middleware\CheckScopes;

class CheckScopesTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
    }

    public function test_request_is_passed_along_if_scopes_are_present_on_token()
    {
        $middleware = new CheckScopes;
        $request = Mockery::mock();
        $request->shouldReceive('user')->andReturn($user = Mockery::mock());
        $user->shouldReceive('token')->andReturn($token = Mockery::mock());
        $user->shouldReceive('tokenCan')->with('foo')->andReturn(true);
        $user->shouldReceive('tokenCan')->with('bar')->andReturn(true);

        $response = $middleware->handle($request, function () {
            return 'response';
        }, 'foo', 'bar');

        $this->assertEquals('response', $response);
    }

    public function test_exception_is_thrown_if_token_doesnt_have_scope()
    {
        $this->expectException(MissingScopeException::class);

        $middleware = new CheckScopes;
        $request = Mockery::mock();
        $request->shouldReceive('user')->andReturn($user = Mockery::mock());
        $user->shouldReceive('token')->andReturn($token = Mockery::mock());
        $user->shouldReceive('tokenCan')->with('foo')->andReturn(false);

        $middleware->handle($request, function () {
            return 'response';
        }, 'foo', 'bar');
    }

    public function test_exception_is_thrown_if_no_authenticated_user()
    {
        $this->expectException(AuthenticationException::class);
        $middleware = new CheckScopes;
        $request = Mockery::mock();
        $request->shouldReceive('user')->once()->andReturn(null);

        $middleware->handle($request, function () {
            return 'response';
        }, 'foo', 'bar');
    }

    public function test_exception_is_thrown_if_no_token()
    {
        $this->expectException(AuthenticationException::class);
        $middleware = new CheckScopes;
        $request = Mockery::mock();
        $request->shouldReceive('user')->andReturn($user = Mockery::mock());
        $user->shouldReceive('token')->andReturn(null);

        $middleware->handle($request, function () {
            return 'response';
        }, 'foo', 'bar');
    }
}
