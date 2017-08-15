<?php

namespace Laravel\Passport;

use Mongolid\Util\LocalDateTime;
use MongolidLaravel\MongolidModel as Model;

class Client extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_clients';

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'personal_access_client' => 'bool',
        'password_client' => 'bool',
        'revoked' => 'bool',
    ];

    /**
     * Get all of the authentication codes for the client.
     *
     * @return \Mongolid\Cursor\Cursor
     */
    public function authCodes()
    {
        return AuthCode::where(['client_id' => $this->_id]);
    }

    /**
     * Get all of the tokens that belong to the client.
     *
     * @param array $query
     *
     * @return \Mongolid\Cursor\Cursor
     */
    public function tokens(array $query = [])
    {
        return Token::where(
            array_merge($query, ['client_id' => $this->_id])
        );
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
     * {@inheritdoc}
     */
    public function toArray()
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
