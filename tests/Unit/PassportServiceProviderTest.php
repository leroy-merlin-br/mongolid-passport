<?php

namespace Laravel\Passport\Tests\Unit;

use Illuminate\Config\Repository as Config;
use Illuminate\Contracts\Foundation\Application as App;
use Illuminate\Foundation\Application;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use Lcobucci\JWT\Parser as JwtParser;
use Lcobucci\JWT\Token\Parser as TokenParser;
use Mockery as m;
use PHPUnit\Framework\TestCase;

class PassportServiceProviderTest extends TestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();

        @unlink(__DIR__.'/../keys/oauth-private.key');
    }

    public function test_can_use_crypto_keys_from_config()
    {
        $privateKey = openssl_pkey_new();

        openssl_pkey_export($privateKey, $privateKeyString);

        $config = m::mock(Config::class, function ($config) use ($privateKeyString) {
            $config->shouldReceive('get')
                ->with('passport.private_key')
                ->andReturn($privateKeyString);
        });

        $provider = new PassportServiceProvider(
            m::mock(App::class, ['make' => $config])
        );

        // Call protected makeCryptKey method
        $cryptKey = (function () {
            return $this->makeCryptKey('private');
        })->call($provider);

        $this->assertSame(
            $privateKeyString,
            $cryptKey->getKeyContents()
        );
    }

    public function test_can_use_crypto_keys_from_local_disk()
    {
        Passport::loadKeysFrom(__DIR__.'/../keys');

        $privateKey = openssl_pkey_new();

        openssl_pkey_export_to_file($privateKey, __DIR__.'/../keys/oauth-private.key');
        openssl_pkey_export($privateKey, $privateKeyString);

        $config = m::mock(Config::class, function ($config) {
            $config->shouldReceive('get')->with('passport.private_key')->andReturn(null);
        });

        $provider = new PassportServiceProvider(
            m::mock(App::class, ['make' => $config])
        );

        // Call protected makeCryptKey method
        $cryptKey = (function () {
            return $this->makeCryptKey('private');
        })->call($provider);

        $this->assertSame(
            $privateKeyString,
            file_get_contents($cryptKey->getKeyPath())
        );

        @unlink(__DIR__.'/../keys/oauth-private.key');
    }

    public function test_registers_the_jwt_parser_contract()
    {
        $app = new Application(__DIR__.'/../..');

        $provider = new class($app) extends PassportServiceProvider {
            public function registerJwtParserForTest()
            {
                $this->registerJWTParser();
            }
        };

        $provider->registerJwtParserForTest();

        $this->assertInstanceOf(TokenParser::class, $app->make(JwtParser::class));
    }
}
