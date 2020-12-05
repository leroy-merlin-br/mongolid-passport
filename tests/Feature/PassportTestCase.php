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

    protected function setUp(): void
    {
        parent::setUp();

        $this->dropDatabase();

        Passport::routes();

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
