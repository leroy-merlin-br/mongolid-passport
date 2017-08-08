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
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'revoked' => 'bool',
    ];

    /**
     * The attributes that should be mutated to dates.
     *
     * @var array
     */
    protected $dates = [
        'expires_at',
    ];

    /**
     * Get the client that owns the authentication code.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function client()
    {
        return $this->hasMany(Client::class);
    }
}
