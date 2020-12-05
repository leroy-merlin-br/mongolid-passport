<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Contracts\Config\Repository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use MongolidLaravel\MongolidServiceProvider;
use Orchestra\Testbench\TestCase;

abstract class PassportTestCase extends TestCase
{
    use DropDatabase;

    const KEYS = __DIR__.'/keys';
    const PUBLIC_KEY = self::KEYS.'/oauth-public.key';
    const PRIVATE_KEY = self::KEYS.'/oauth-private.key';

    protected function setUp(): void
    {
        parent::setUp();

        $this->dropDatabase();

        Passport::routes();

        @unlink(self::PUBLIC_KEY);
        @unlink(self::PRIVATE_KEY);

        $this->artisan('passport:keys');
    }

    protected function tearDown(): void
    {
        $this->dropDatabase();

        parent::tearDown();
    }

    protected function getEnvironmentSetUp($app)
    {
        $config = $app->make(Repository::class);

        $config->set('auth.defaults.provider', 'mongolid');

        if (($userClass = $this->getUserClass()) !== null) {
            $config->set('auth.providers.mongolid.driver', 'mongolid');
            $config->set('auth.providers.mongolid.model', $userClass);
        }

        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'mongolid']);
        $config->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'mongolid']);

        $app['config']->set('database.mongodb.default', [
            'cluster' => [
                'nodes' => [
                    'primary' => [
                        'host' => 'db',
                        'port' => 27017,
                    ],
                ],
            ],
            'database' => 'testing',
        ]);

        $app['config']->set('passport.storage.database.connection', 'mongolid');

        $app['config']->set('database.mongodb.connections.mongolid', [
            'cluster' => [
                'nodes' => [
                    'primary' => [
                        'host' => 'db',
                        'port' => 27017,
                    ],
                ],
            ],
            'database' => 'mongolid',
        ]);
    }

    protected function getPackageProviders($app)
    {
        return [
            PassportServiceProvider::class,
            MongolidServiceProvider::class,
        ];
    }

    /**
     * Get the Eloquent user model class name.
     *
     * @return string|null
     */
    protected function getUserClass()
    {
    }
}
