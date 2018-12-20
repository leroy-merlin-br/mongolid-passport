<?php

namespace Laravel\Passport\Bridge;

use MongoDB\BSON\UTCDateTime;
use Laravel\Passport\AuthCode as AuthCodeModel;
use Laravel\Passport\Passport;
use Illuminate\Database\Connection;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    use FormatsScopesForStorage;

    /**
     * {@inheritdoc}
     */
    public function getNewAuthCode()
    {
        return new AuthCode;
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity)
    {
        $authCode = AuthCodeModel::fill(
            [
                '_id' => $authCodeEntity->getIdentifier(),
                'user_id' => $authCodeEntity->getUserIdentifier(),
                'client_id' => $authCodeEntity->getClient()->getIdentifier(),
                'scopes' => $this->formatScopesForStorage($authCodeEntity->getScopes()),
                'revoked' => false,
                'expires_at' => new UTCDateTime($authCodeEntity->getExpiryDateTime()),
            ]
        );

        $authCode->save();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAuthCode($codeId)
    {
        if ($authCode = AuthCodeModel::first($codeId)) {
            $authCode->revoked = true;

            $authCode->save();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthCodeRevoked($codeId)
    {
        $authCode = AuthCodeModel::first($codeId);

        return $authCode && $authCode->revoked;
    }
}
