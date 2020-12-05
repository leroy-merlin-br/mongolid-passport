<?php

namespace Laravel\Passport\Tests\Feature;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Factory;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\HasApiTokens;
use Laravel\Passport\Token;
use Laravel\Passport\TokenRepository;
use Lcobucci\JWT\Configuration;
use MongolidLaravel\MongolidModel as Model;

class AccessTokenControllerTest extends PassportTestCase
{
    protected function getUserClass()
    {
        return User::class;
    }

    public function testGettingAccessTokenWithPasswordGrant()
    {
        $this->withoutExceptionHandling();

        $password = 'foobar123';
        $user = new User();
        $user->email = 'foo@gmail.com';
        $user->password = $this->app->make(Hasher::class)->make($password);
        $user->save();

        $client = new Client();
        $client->fill([
            'user_id' => $user->_id,
            'name' => 'Some Company',
            'secret' => Str::random(40),
            'redirect' => 'http://some-company.com',
            'personal_access_client' => false,
            'password_client' => true,
            'revoked' => false,
        ]);
        $client->save();

        $response = $this->post(
            '/oauth/token',
            [
                'grant_type' => 'password',
                'client_id' => (string) $client->_id,
                'client_secret' => $client->secret,
                'username' => $user->email,
                'password' => $password,
            ]
        );

        $response->assertOk();

        $response->assertHeader('pragma', 'no-cache');
        $response->assertHeader('cache-control', 'no-store, private');
        $response->assertHeader('content-type', 'application/json; charset=UTF-8');

        $decodedResponse = $response->decodeResponseJson();

        $this->assertArrayHasKey('token_type', $decodedResponse);
        $this->assertArrayHasKey('expires_in', $decodedResponse);
        $this->assertArrayHasKey('access_token', $decodedResponse);
        $this->assertArrayHasKey('refresh_token', $decodedResponse);
        $this->assertSame('Bearer', $decodedResponse['token_type']);
        $expiresInSeconds = 31536000;
        $this->assertEqualsWithDelta($expiresInSeconds, $decodedResponse['expires_in'], 5);

        $jwtAccessToken = Configuration::forUnsecuredSigner()->parser()->parse($decodedResponse['access_token']);
        $this->assertEquals($client, $this->app->make(ClientRepository::class)->findActive($jwtAccessToken->claims()->get('aud')));
        $this->assertEquals($user, $this->app->make('auth')->createUserProvider()->retrieveById($jwtAccessToken->claims()->get('sub')));

        $token = $this->app->make(TokenRepository::class)->find($jwtAccessToken->claims()->get('jti'));
        $this->assertInstanceOf(Token::class, $token);
        $this->assertFalse($token->revoked);
        $this->assertEquals($user, $token->user());
        $this->assertEquals($client, $token->client());
        $this->assertNull($token->name);
        $this->assertLessThanOrEqual(5, CarbonImmutable::now()->addSeconds($expiresInSeconds)->diffInSeconds($token->expires_at->toDateTime()));
    }

    public function testGettingAccessTokenWithPasswordGrantWithInvalidPassword()
    {
        $password = 'foobar123';
        $user = new User();
        $user->email = 'foo@gmail.com';
        $user->password = $this->app->make(Hasher::class)->make($password);
        $user->save();

        $client = new Client();
        $client->fill([
            'user_id' => $user->_id,
            'name' => 'Some Company',
            'secret' => Str::random(40),
            'redirect' => 'http://some-company.com',
            'personal_access_client' => false,
            'password_client' => true,
            'revoked' => false,
        ]);
        $client->save();

        $response = $this->post(
            '/oauth/token',
            [
                'grant_type' => 'password',
                'client_id' => (string) $client->_id,
                'client_secret' => $client->secret,
                'username' => $user->email,
                'password' => $password.'foo',
            ]
        );

        $response->assertStatus(400);

        $response->assertHeader('cache-control', 'no-cache, private');
        $response->assertHeader('content-type', 'application/json');

        $decodedResponse = $response->decodeResponseJson();

        $this->assertArrayNotHasKey('token_type', $decodedResponse);
        $this->assertArrayNotHasKey('expires_in', $decodedResponse);
        $this->assertArrayNotHasKey('access_token', $decodedResponse);
        $this->assertArrayNotHasKey('refresh_token', $decodedResponse);

        $this->assertArrayHasKey('error', $decodedResponse);
        $this->assertSame('invalid_grant', $decodedResponse['error']);
        $this->assertArrayHasKey('error_description', $decodedResponse);
        $this->assertArrayHasKey('hint', $decodedResponse);
        $this->assertArrayHasKey('message', $decodedResponse);

        $this->assertSame(0, Token::all()->count());
    }

    public function testGettingAccessTokenWithPasswordGrantWithInvalidClientSecret()
    {
        $password = 'foobar123';
        $user = new User();
        $user->email = 'foo@gmail.com';
        $user->password = $this->app->make(Hasher::class)->make($password);
        $user->save();

        $client = new Client();
        $client->fill([
            'user_id' => $user->_id,
            'name' => 'Some Company',
            'secret' => Str::random(40),
            'redirect' => 'http://some-company.com',
            'personal_access_client' => false,
            'password_client' => true,
            'revoked' => false,
        ]);
        $client->save();

        $response = $this->post(
            '/oauth/token',
            [
                'grant_type' => 'password',
                'client_id' => (string) $client->_id,
                'client_secret' => $client->secret.'foo',
                'username' => $user->email,
                'password' => $password,
            ]
        );

        $response->assertStatus(401);

        $response->assertHeader('cache-control', 'no-cache, private');
        $response->assertHeader('content-type', 'application/json');

        $decodedResponse = $response->decodeResponseJson();

        $this->assertArrayNotHasKey('token_type', $decodedResponse);
        $this->assertArrayNotHasKey('expires_in', $decodedResponse);
        $this->assertArrayNotHasKey('access_token', $decodedResponse);
        $this->assertArrayNotHasKey('refresh_token', $decodedResponse);

        $this->assertArrayHasKey('error', $decodedResponse);
        $this->assertSame('invalid_client', $decodedResponse['error']);
        $this->assertArrayHasKey('error_description', $decodedResponse);
        $this->assertSame('Client authentication failed', $decodedResponse['error_description']);
        $this->assertArrayNotHasKey('hint', $decodedResponse);
        $this->assertArrayHasKey('message', $decodedResponse);
        $this->assertSame('Client authentication failed', $decodedResponse['message']);

        $this->assertSame(0, Token::all()->count());
    }
}

class User extends Model
{
    use HasApiTokens;

    protected $collection = 'users';

    public function getAuthIdentifier()
    {
        return $this->_id;
    }

    public function getAuthPassword()
    {
        return $this->password;
    }
}
