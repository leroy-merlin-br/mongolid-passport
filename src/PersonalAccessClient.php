<?php

namespace Laravel\Passport;

use MongolidLaravel\MongolidModel as Model;

class PersonalAccessClient extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_personal_access_clients';

    /**
     * Get all of the authentication codes for the client.
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
