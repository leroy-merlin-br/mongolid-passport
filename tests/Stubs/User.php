<?php

namespace Laravel\Passport\Tests\Stubs;

use MongolidLaravel\LegacyMongolidModel;

class User extends LegacyMongolidModel
{
    protected $collection = 'users';
}
