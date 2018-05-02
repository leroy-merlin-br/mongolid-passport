<?php

namespace Laravel\Passport\Bridge;

use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class ScopeRepository implements ScopeRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getScopeEntityByIdentifier($identifier)
    {
        if (Passport::hasScope($identifier)) {
            return new Scope($identifier);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeScopes(
        array $scopes, $grantType,
        ClientEntityInterface $clientEntity, $userIdentifier = null)
    {
        $this->validateClientScopes($scopes, $clientEntity);

        if (! in_array($grantType, ['password', 'personal_access'])) {
            $scopes = collect($scopes)->reject(function ($scope) {
                return trim($scope->getIdentifier()) === '*';
            })->values()->all();
        }

        return collect($scopes)->filter(function ($scope) {
            return Passport::hasScope($scope->getIdentifier());
        })->values()->all();
    }

    /**
     * Checks if the requested scopes match with
     * scopes allowed for the client.
     *
     * @throws OAuthServerException
     *
     * @param array                 $scopes
     * @param ClientEntityInterface $clientEntity
     *
     * @return bool
     */
    public function validateClientScopes(
        array $scopes,
        ClientEntityInterface $clientEntity
    ) {
        if (!$clientAllowedScopes = $clientEntity->getAllowedScopes()) {
            return true;
        }

        collect($scopes)->each(function ($scope) use ($clientAllowedScopes) {
            $scopeIdentifier = trim($scope->getIdentifier());

            if (!in_array($scopeIdentifier, $clientAllowedScopes)) {
                throw OAuthServerException::invalidScope($scopeIdentifier);
            }
        });

        return true;
    }
}
