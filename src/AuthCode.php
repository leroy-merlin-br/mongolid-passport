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
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * The "type" of the primary key ID.
     *
     * @var string
     */
    protected $keyType = '\MongoDB\BSON\ObjectId';

    /**
     * Get the client that owns the authentication code.
     *
     * @return Client|null
     */
    public function client()
    {
        return $this->referencesOne(Client::class, 'client_id');
    }
}
