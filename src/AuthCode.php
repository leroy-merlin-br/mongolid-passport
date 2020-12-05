<?php

namespace Laravel\Passport;

use MongolidLaravel\MongolidModel as Model;

class AuthCode extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_auth_codes';

    /**
     * Get the client that owns the authentication code.
     *
     * @return Client|null
     */
    public function client()
    {
        return $this->referencesOne(Client::class, 'client_id');
    }

    /**
     * Get the current connection name for the model.
     *
     * @return string|null
     */
    public function getConnectionName()
    {
        return config('passport.storage.database.connection') ?? $this->connection;
    }
}
