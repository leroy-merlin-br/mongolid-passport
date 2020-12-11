<?php

namespace Laravel\Passport;

class RefreshTokenRepository
{
    /**
     * Creates a new refresh token.
     *
     * @param  array  $attributes
     * @return \Laravel\Passport\RefreshToken
     */
    public function create($attributes)
    {
        $refreshToken = Passport::refreshToken();
        $refreshToken->fill($attributes);
        $refreshToken->save();

        return $refreshToken;
    }

    /**
     * Gets a refresh token by the given ID.
     *
     * @param  string  $id
     * @return \Laravel\Passport\RefreshToken
     */
    public function find($id)
    {
        $refreshTokenModel = Passport::refreshTokenModel();

        return $refreshTokenModel::first($id);
    }

    /**
     * Stores the given token instance.
     *
     * @param  \Laravel\Passport\RefreshToken  $token
     * @return void
     */
    public function save(RefreshToken $token)
    {
        $token->save();
    }

    /**
     * Revokes the refresh token.
     *
     * @param  string  $id
     * @return bool
     */
    public function revokeRefreshToken($id)
    {
        if ($refreshToken = $this->find($id)) {
            return $refreshToken->revoke();
        }

        return true;
    }

    /**
     * Revokes refresh tokens by access token id.
     *
     * @param  string  $tokenId
     * @return void
     */
    public function revokeRefreshTokensByAccessTokenId($tokenId)
    {
        $refreshTokens = Passport::refreshToken()->where(['access_token_id' => $tokenId]);

        foreach ($refreshTokens as $refreshToken) {
            $refreshToken->revoke();
        }
    }

    /**
     * Checks if the refresh token has been revoked.
     *
     * @param  string  $id
     * @return bool
     */
    public function isRefreshTokenRevoked($id)
    {
        if ($token = $this->find($id)) {
            return (bool) $token->revoked;
        }

        return true;
    }
}
