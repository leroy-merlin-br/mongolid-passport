<?php

namespace Laravel\Passport\Tests\Feature;

use Mongolid\Connection\Pool;

trait DropDatabase
{
    /**
     * Define hooks to migrate the database before and after each test.
     *
     * @return void
     */
    public function dropDatabase()
    {
        $pool = app(Pool::class);

        $pool->getConnection()
            ->getRawConnection()
            ->dropDatabase($pool->getConnection()->defaultDatabase);
    }
}
