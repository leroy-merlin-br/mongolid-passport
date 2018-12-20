<?php

namespace Laravel\Passport;

use Mongolid\Laravel\AbstractModel as Model;

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
     * Get the client that owns the authentication code.
     *
     * @return Client|null
     */
    public function client()
    {
        return $this->referencesOne(Client::class, 'client_id');
    }
}
