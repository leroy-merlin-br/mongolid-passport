<?php

namespace Laravel\Passport\Bridge;

use MongoDB\BSON\UTCDateTime;
use Laravel\Passport\Passport;
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
        $authCode = Passport::authCode();

        $authCode->fill(
            [
                '_id' => $authCodeEntity->getIdentifier(),
                'user_id' => $authCodeEntity->getUserIdentifier(),
                'client_id' => $authCodeEntity->getClient()->getIdentifier(),
                'scopes' => $this->formatScopesForStorage($authCodeEntity->getScopes()),
                'revoked' => false,
                'expires_at' => new UTCDateTime($authCodeEntity->getExpiryDateTime()),
            ],
            true
        );

        $authCode->save();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAuthCode($codeId)
    {
        if ($authCode = (Passport::authCodeModel())::first($codeId)) {
            $authCode->revoked = true;

            $authCode->save();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthCodeRevoked($codeId)
    {
        $authCode = (Passport::authCodeModel())::first($codeId);

        return $authCode && $authCode->revoked;
    }
}
