<?php

namespace Laravel\Passport;

use Mongolid\Laravel\AbstractModel as Model;

class PersonalAccessClient extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_personal_access_clients';

    /**
     * The guarded attributes on the model.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * Get all of the authentication codes for the client.
     *
     * @return Client|null
     */
    public function client()
    {
        return $this->referencesOne(Client::class, 'client_id');
    }
}
