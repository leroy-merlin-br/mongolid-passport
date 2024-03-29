<?php

namespace Laravel\Passport\Tests\Unit;

use Illuminate\Contracts\Validation\Factory;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Http\Controllers\PersonalAccessTokenController;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Laravel\Passport\TokenRepository;
use Mockery as m;
use MongoDB\BSON\ObjectId;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

class PersonalAccessTokenControllerTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function test_tokens_can_be_retrieved_for_users()
    {
        $request = Request::create('/', 'GET');

        $client1 = m::mock(Client::class)->makePartial();
        $client1->fill([
            '_id' => new ObjectId(),
            'personal_access_client' => true,
        ]);
        $client2 = m::mock(Client::class)->makePartial();
        $client2->fill([
            '_id' => new ObjectId(),
            'personal_access_client' => false,
        ]);

        $token1 = m::mock(Token::class)->makePartial();
        $token1->revoked = false;
        $token2 = m::mock(Token::class)->makePartial();
        $token2->revoked = false;

        $userTokens = [$token1, $token2];

        $token1->shouldReceive('client')->twice()->andReturn($client1);
        $token2->shouldReceive('client')->twice()->andReturn($client2);

        $tokenRepository = m::mock(TokenRepository::class);
        $tokenRepository->shouldReceive('forUser')->andReturn($userTokens);

        $request->setUserResolver(function () {
            $user = m::mock();
            $user->shouldReceive('getAuthIdentifier')->andReturn(1);

            return $user;
        });

        $validator = m::mock(Factory::class);
        $controller = new PersonalAccessTokenController($tokenRepository, $validator);

        $this->assertCount(1, $controller->forUser($request));
        $this->assertEquals($token1, $controller->forUser($request)[0]);
    }

    public function test_tokens_can_be_updated()
    {
        Passport::tokensCan([
            'user' => 'first',
            'user-admin' => 'second',
        ]);

        $request = Request::create('/', 'GET', ['name' => 'token name', 'scopes' => ['user', 'user-admin']]);

        $request->setUserResolver(function () {
            $user = m::mock();
            $user->shouldReceive('createToken')
                ->once()
                ->with('token name', ['user', 'user-admin'])
                ->andReturn('response');

            return $user;
        });

        $validator = m::mock(Factory::class);
        $validator->shouldReceive('make')->once()->with([
            'name' => 'token name',
            'scopes' => ['user', 'user-admin'],
        ], [
            'name' => 'required|max:191',
            'scopes' => 'array|in:'.implode(',', Passport::scopeIds()),
        ])->andReturn($validator);
        $validator->shouldReceive('validate')->once();

        $tokenRepository = m::mock(TokenRepository::class);
        $controller = new PersonalAccessTokenController($tokenRepository, $validator);

        $this->assertSame('response', $controller->store($request));
    }

    public function test_tokens_can_be_deleted()
    {
        $request = Request::create('/', 'GET');

        $token1 = m::mock(Token::class.'[revoke]');
        $token1->_id = 1;
        $token1->shouldReceive('revoke')->once();

        $tokenRepository = m::mock(TokenRepository::class);
        $tokenRepository->shouldReceive('findForUser')->andReturn($token1);

        $request->setUserResolver(function () {
            $user = m::mock();
            $user->shouldReceive('getAuthIdentifier')->andReturn(1);

            return $user;
        });

        $validator = m::mock(Factory::class);
        $controller = new PersonalAccessTokenController($tokenRepository, $validator);

        $response = $controller->destroy($request, 1);

        $this->assertSame(Response::HTTP_NO_CONTENT, $response->status());
    }

    public function test_not_found_response_is_returned_if_user_doesnt_have_token()
    {
        $request = Request::create('/', 'GET');

        $tokenRepository = m::mock(TokenRepository::class);
        $tokenRepository->shouldReceive('findForUser')->with(3, 1)->andReturnNull();

        $request->setUserResolver(function () {
            $user = m::mock();
            $user->shouldReceive('getAuthIdentifier')->andReturn(1);

            return $user;
        });

        $validator = m::mock(Factory::class);
        $controller = new PersonalAccessTokenController($tokenRepository, $validator);

        $this->assertSame(404, $controller->destroy($request, 3)->status());
    }
}
