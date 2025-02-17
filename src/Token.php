<?php

namespace Laravel\Passport;

use Illuminate\Contracts\Auth\Authenticatable;
use MongolidLaravel\LegacyMongolidModel as Model;

class Token extends Model
{
    /**
     * {@inheritdoc}
     */
    protected ?string $collection = 'oauth_access_tokens';

    /**
     * Get the client that the token belongs to.
     */
    public function client(): ?Client
    {
        return $this->referencesOne(Client::class, 'client_id');
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
     */
    public function can(string $scope): bool
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
     * Resolve all possible scopes.
     */
    protected function resolveInheritedScopes(string $scope): array
    {
        $parts = explode(':', $scope);

        $partsCount = count($parts);

        $scopes = [];

        for ($i = 1; $i <= $partsCount; $i++) {
            $scopes[] = implode(':', array_slice($parts, 0, $i));
        }

        return $scopes;
    }

    /**
     * Determine if the token is missing a given scope.
     */
    public function cant(string $scope): bool
    {
        return ! $this->can($scope);
    }

    /**
     * Revoke the token instance.
     */
    public function revoke(): bool
    {
        $this->fill(['revoked' => true], true);

        return $this->save();
    }

    /**
     * Determine if the token is a transient JWT token.
     */
    public function transient(): bool
    {
        return false;
    }
}
