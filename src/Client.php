<?php

namespace Laravel\Passport;

use Mongolid\Util\LocalDateTime;
use MongolidLaravel\LegacyMongolidModel as Model;

class Client extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_clients';

    /**
     * The guarded attributes on the model.
     *
     * @var array
     */
    protected $guarded = [];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'secret',
    ];

    /**
     * The temporary plain-text client secret.
     *
     * @var string|null
     */
    protected $plainSecret;

    /**
     * {@inheritdoc}
     */
    public $mutable = true;

    /**
     * Get the user that the client belongs to.
     */
    public function user()
    {
        $provider = $this->provider ?: config('auth.guards.api.provider');

        $this->referencesOne(
            config("auth.providers.{$provider}.model"),
            'user_id'
        );
    }

    /**
     * Get all of the authentication codes for the client.
     *
     * @return \Mongolid\Cursor\CursorInterface
     */
    public function authCodes()
    {
        $authCodeModel = Passport::authCodeModel();

        return $authCodeModel::where(['client_id' => (string) $this->_id]);
    }

    /**
     * Get all of the tokens that belong to the client.
     *
     * @param array $query
     *
     * @return \Mongolid\Cursor\CursorInterface
     */
    public function tokens(array $query = [])
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
     *
     * @return string|null
     */
    public function getPlainSecretAttribute()
    {
        return $this->plainSecret;
    }

    /**
     * Set the value of the secret attribute.
     *
     * @param  string|null  $value
     */
    public function setSecretAttribute($value): string
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
     *
     * @return bool
     */
    public function firstParty()
    {
        return $this->personal_access_client || $this->password_client;
    }

    /**
     * Determine if the client should skip the authorization prompt.
     *
     * @return bool
     */
    public function skipsAuthorization()
    {
        return false;
    }

    /**
     * Determine if the client is a confidential client.
     *
     * @return bool
     */
    public function confidential()
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
