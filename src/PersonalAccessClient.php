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
     * The guarded attributes on the model.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * Get all of the authentication codes for the client.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function client()
    {
        return $this->belongsTo(Client::class);
    }
}
