<?php

namespace Laravel\Passport\Tests\Feature;

use Mongolid\Connection\Connection;

trait DropDatabase
{
    /**
     * Define hooks to migrate the database before and after each test.
     *
     * @return void
     */
    public function dropDatabase()
    {
        $connection = app(Connection::class);

        $connection->getClient()
            ->dropDatabase($connection->defaultDatabase);
    }
}
