<?php

namespace Laravel\Passport;

use MongoDB\BSON\UTCDateTime;
use Mongolid\Laravel\AbstractModel as Model;

class TokenRepository
{
    /**
     * Creates a new Access Token.
     *
     * @param  array $attributes
     *
     * @return \Laravel\Passport\Token
     */
    public function create($attributes)
    {
        $token = Token::fill($attributes);
        $token->save();

        return $token;
    }

    /**
     * Get a token by the given ID.
     *
     * @param  string $id
     *
     * @return \Laravel\Passport\Token|null
     */
    public function find($id)
    {
        return Token::first($id);
    }

    /**
     * Get a token by the given user ID and token ID.
     *
     * @param  string $id
     * @param  int    $userId
     *
     * @return \Laravel\Passport\Token|null
     */
    public function findForUser($id, $userId)
    {
        return Token::first(['_id' => (string) $id, 'user_id' => (string) $userId]);
    }

    /**
     * Get the token instances for the given user ID.
     *
     * @param  mixed $userId
     *
     * @return \Mongolid\Cursor\Cursor
     */
    public function forUser($userId)
    {
        return Token::where(['user_id' => (string) $userId]);
    }

    /**
     * Get a valid token instance for the given user and client.
     *
     * @param  Model                    $user
     * @param  \Laravel\Passport\Client $client
     *
     * @return \Laravel\Passport\Token|null
     */
    public function getValidToken($user, $client)
    {
        return $client->tokens(
            [
                'user_id' => (string) $user->getKey(),
                'revoked' => false,
                'expires_at' => ['$gt' => new UTCDateTime()],
            ]
        )
            ->first();
    }

    /**
     * Store the given token instance.
     *
     * @param  \Laravel\Passport\Token $token
     *
     * @return void
     */
    public function save(Token $token)
    {
        $token->save();
    }

    /**
     * Revoke an access token.
     *
     * @param  string $id
     *
     * @return mixed
     */
    public function revokeAccessToken($id)
    {
        if ($token = $this->find($id)) {
            $token->revoked = true;

            return $token->update();
        }

        return true;
    }

    /**
     * Check if the access token has been revoked.
     *
     * @param  string $id
     *
     * @return bool Return true if this token has been revoked
     */
    public function isAccessTokenRevoked($id)
    {
        if ($token = $this->find($id)) {
            return (bool) $token->revoked;
        }

        return true;
    }

    /**
     * Find a valid token for the given user and client.
     *
     * @param  Model                    $user
     * @param  \Laravel\Passport\Client $client
     *
     * @return \Laravel\Passport\Token|null
     */
    public function findValidToken($user, $client)
    {
        $where = [
            'user_id' => (string) $user->getKey(),
            'revoked' => false,
            'expires_at' => ['$gt' => new UTCDateTime()],
        ];

        return $client->tokens($where)->sort(['expires_at' => -1])->first();
    }
}
