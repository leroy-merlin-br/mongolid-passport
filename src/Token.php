<?php

namespace Laravel\Passport;

use Illuminate\Contracts\Auth\Authenticatable;
use MongolidLaravel\LegacyMongolidModel as Model;

class Token extends Model
{
    use ResolvesInheritedScopes;

    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_access_tokens';

    /**
     * Get the client that the token belongs to.
     *
     * @return Client|null
     */
    public function client()
    {
        return $this->referencesOne(Client::class, 'client_id');
    }

    /**
     * Get the refresh token associated with the token.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasOne
     */
    public function refreshToken()
    {
        return $this->hasOne(Passport::refreshTokenModel(), 'access_token_id');
    }

    /**
     * Get the user that the token belongs to.
     *
     * @return Authenticatable|null
     */
    public function user()
    {
        $provider = config('auth.guards.api.provider');

        $model = config('auth.providers.'.$provider.'.model');

        return $this->referencesOne($model, 'user_id');
    }

    /**
     * Determine if the token has a given scope.
     *
     * @param  string  $scope
     * @return bool
     */
    public function can($scope)
    {
        if (in_array('*', $this->scopes)) {
            return true;
        }

        $scopes = Passport::$withInheritedScopes
            ? $this->resolveInheritedScopes($scope)
            : [$scope];

        foreach ($scopes as $scope) {
            if (array_key_exists($scope, array_flip($this->scopes))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the token is missing a given scope.
     *
     * @param  string  $scope
     * @return bool
     */
    public function cant($scope)
    {
        return ! $this->can($scope);
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
