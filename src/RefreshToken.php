<?php

namespace Laravel\Passport;

use MongolidLaravel\LegacyMongolidModel as Model;

class RefreshToken extends Model
{
    /**
     * {@inheritdoc}
     */
    protected ?string $collection = 'oauth_refresh_tokens';

    /**
     * The guarded attributes on the model.
     */
    protected array $guarded = [];

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
}
