<?php

namespace Laravel\Passport;

use Mongolid\Cursor\CursorInterface;
use Mongolid\Util\LocalDateTime;
use MongolidLaravel\LegacyMongolidModel as Model;

class Client extends Model
{
    /**
     * {@inheritdoc}
     */
    protected ?string $collection = 'oauth_clients';

    /**
     * The guarded attributes on the model.
     */
    protected array $guarded = [];

    /**
     * The attributes excluded from the model's JSON form.
     */
    protected array $hidden = [
        'secret',
    ];

    /**
     * The temporary plain-text client secret.
     */
    protected ?string $plainSecret;

    /**
     * {@inheritdoc}
     */
    public bool $mutable = true;

    /**
     * Get the user that the client belongs to.
     */
    public function user(): void
    {
        $provider = $this->provider ?: config('auth.guards.api.provider');

        $this->referencesOne(
            config("auth.providers.{$provider}.model"),
            'user_id'
        );
    }

    /**
     * Get all the authentication codes for the client.
     */
    public function authCodes(): CursorInterface
    {
        $authCodeModel = Passport::authCodeModel();

        return $authCodeModel::where(['client_id' => (string) $this->_id]);
    }

    /**
     * Get all the tokens that belong to the client.
     */
    public function tokens(array $query = []): CursorInterface
    {
        $tokenModel = Passport::tokenModel();

        return $tokenModel::where(
            array_merge($query, ['client_id' => (string) $this->_id])
        );
    }

    /**
     * The temporary non-hashed client secret.
     *
     * This is only available once during the request that created the client.
     */
    public function getPlainSecretAttribute(): ?string
    {
        return $this->plainSecret;
    }

    /**
     * Set the value of the secret attribute.
     */
    public function setSecretAttribute(?string $value): string
    {
        $this->plainSecret = $value;

        if (is_null($value) || ! Passport::$hashesClientSecrets) {
            return $value;
        }

        if (password_get_info($value)['algoName'] === PASSWORD_BCRYPT) {
            return $value;
        }


        return password_hash($value, PASSWORD_BCRYPT);
    }

    /**
     * Determine if the client is a "first party" client.
     */
    public function firstParty(): bool
    {
        return $this->personal_access_client || $this->password_client;
    }

    /**
     * Determine if the client should skip the authorization prompt.
     */
    public function skipsAuthorization(): bool
    {
        return false;
    }

    /**
     * Determine if the client is a confidential client.
     */
    public function confidential(): bool
    {
        return ! empty($this->secret);
    }

    /**
     * {@inheritdoc}
     */
    public function toArray(): array
    {
        return [
            'id' => (string) $this->_id,
            'user_id' => (string) $this->user_id,
            'name' => $this->name,
            'redirect' => $this->redirect,
            'personal_access_client' => (bool) $this->personal_access_client,
            'password_client' => (bool) $this->password_client,
            'revoked' => (bool) $this->revoked,
            'created_at' => LocalDateTime::format($this->created_at, 'Y-m-d H:i:s'),
            'updated_at' => LocalDateTime::format($this->updated_at, 'Y-m-d H:i:s'),
        ];
    }
}
