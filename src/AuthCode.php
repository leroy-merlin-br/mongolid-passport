<?php

namespace Laravel\Passport;

use MongolidLaravel\LegacyMongolidModel as Model;

class AuthCode extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_auth_codes';

    /**
     * Get the client that owns the authentication code.
     */
    public function client()
    {
        return $this->referencesOne(Client::class, 'client_id');
    }
}
