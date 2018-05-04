<?php

namespace Laravel\Passport\Bridge;

use Laravel\Passport\Bridge\ScopedClientInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class Client implements ScopedClientInterface
{
    use ClientTrait, EntityTrait;

    /**
     * @var string[]
     */
    protected $allowedScopes;

    /**
     * Create a new client instance.
     *
     * @param  string $identifier
     * @param  string $name
     * @param  string $redirectUri
     * @param  mixed  $allowedScopes
     * @return void
     */
    public function __construct($identifier, $name, $redirectUri, $allowedScopes = null)
    {
        $this->setIdentifier($identifier);
        $this->setAllowedScopes($allowedScopes);

        $this->name = $name;
        $this->redirectUri = explode(',', $redirectUri);
    }

    /**
     * Get the client's allowed scopes.
     * This can be an empty array in cases where the client
     * can not request any scope, an array of specific scopes
     * or a wild card '*'.
     *
     * @return array
     */
    public function getAllowedScopes()
    {
        return array_filter($this->allowedScopes);
    }

    /**
     * Set allowed scopes attributes converting optional
     * param $allowedScopes to array.
     *
     * @param mixed $allowedScopes
     */
    protected function setAllowedScopes($allowedScopes = null)
    {
        if (empty($allowedScopes)) {
            $this->allowedScopes = [];

            return;
        }

        if (is_array($allowedScopes)) {
            $this->allowedScopes = $allowedScopes;
        } elseif(is_string($allowedScopes)) {
            $this->allowedScopes = explode(',', trim($allowedScopes));
        }

        array_walk($this->allowedScopes, 'trim');
    }
}
