<?php

namespace Laravel\Passport\Bridge;

use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Events\RefreshTokenCreated;
use Laravel\Passport\RefreshToken as RefreshTokenModel;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /**
     * The access token repository instance.
     *
     * @var \Laravel\Passport\Bridge\AccessTokenRepository
     */
    protected $tokens;

    /**
     * The event dispatcher instance.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * Create a new repository instance.
     *
     * @param  \Laravel\Passport\Bridge\AccessTokenRepository $tokens
     * @param  \Illuminate\Contracts\Events\Dispatcher        $events
     *
     * @return void
     */
    public function __construct(
        AccessTokenRepository $tokens,
        Dispatcher $events
    ) {
        $this->events = $events;
        $this->tokens = $tokens;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewRefreshToken()
    {
        return new RefreshToken;
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity)
    {
        $refreshToken = new RefreshTokenModel();
        $refreshToken->fill(
            [
                '_id' => $id = $refreshTokenEntity->getIdentifier(),
                'access_token_id' => $accessTokenId = $refreshTokenEntity->getAccessToken()->getIdentifier(),
                'revoked' => false,
                'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
            ]
        );

        $refreshToken->save();

        $this->events->fire(new RefreshTokenCreated($id, $accessTokenId));
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRefreshToken($tokenId)
    {
        if ($refreshToken = RefreshTokenModel::first($tokenId)) {
            $refreshToken->revoked = true;

            $refreshToken->save();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenRevoked($tokenId)
    {
        $refreshToken = RefreshTokenModel::first($tokenId);

        if (!$refreshToken || $refreshToken->revoked) {
            return true;
        }

        return $this->tokens->isAccessTokenRevoked(
            $refreshToken->access_token_id
        );
    }
}
