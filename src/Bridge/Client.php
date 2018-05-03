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
     * If this is empty, the client will be able to request
     * all scopes (no restriction).
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
     * When the client has no scopes restrictions, an empty array is
     * set, every scope requested will be allowed.
     *
     * @param mixed $allowedScopes
     */
    protected function setAllowedScopes($allowedScopes = null)
    {
        if (!$this->hasScopeRestrictions($allowedScopes)) {
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

    /**
     * If the client has no allowed scopes defined or the string '*',
     * it means the client has no scope restrictions.
     * Allowing all scopes for a client that has no allowed scopes definied
     * is intended to maintain compatibility with the original behavior.
     *
     * @param mixed $allowedScopes
     *
     * @return bool
     */
    protected function hasScopeRestrictions($allowedScopes = null)
    {
        return !empty($allowedScopes) && '*' !== $allowedScopes;
    }
}
