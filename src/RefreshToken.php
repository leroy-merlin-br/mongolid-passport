<?php

namespace Laravel\Passport;

use MongolidLaravel\LegacyMongolidModel as Model;

class RefreshToken extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_refresh_tokens';

    /**
     * The guarded attributes on the model.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * Get the access token that the refresh token belongs to.
     */
    public function accessToken()
    {
        return $this->referencesOne(Passport::tokenModel(), 'access_token_id');
    }

    /**
     * Revoke the token instance.
     *
     * @return bool
     */
    public function revoke()
    {
        $this->fill(['revoked' => true], true);

        return $this->save();
    }

    /**
     * Determine if the token is a transient JWT token.
     *
     * @return bool
     */
    public function transient()
    {
        return false;
    }

    /**
     * Get the current connection name for the model.
     *
     * @return string|null
     */
    public function getConnectionName()
    {
        return $this->connection ?? config('passport.connection');
    }
}
