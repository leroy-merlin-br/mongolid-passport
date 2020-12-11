<?php

namespace Laravel\Passport\Tests\Feature\Console;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Laravel\Passport\Tests\Feature\PassportTestCase;

class HashCommandTest extends PassportTestCase
{
    public function test_it_can_properly_hash_client_secrets()
    {
        $client = new Client();
        $client->fill([
            'user_id' => null,
            'name' => 'Some Company',
            'secret' => $secret = Str::random(40),
            'redirect' => 'http://some-company.com',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);
        $client->save();
        $hasher = $this->app->make(Hasher::class);

        Passport::hashClientSecrets();

        $this->artisan('passport:hash', ['--force' => true]);

        $this->assertTrue($hasher->check($secret, $client->first()->secret));

        Passport::$hashesClientSecrets = false;
    }
}
