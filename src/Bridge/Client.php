<?php

namespace Laravel\Passport\Bridge;

use Laravel\Passport\Bridge\ScopedClientInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;

class Client implements ScopedClientInterface
{
    use ClientTrait;

    /**
     * The client identifier.
     *
     * @var string
     */
    protected $identifier;

    /**
     * The client's provider.
     *
     * @var string
     */
    public $provider;

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
     * @param  bool   $isConfidential
     * @param  string|null  $provider
     * @param  mixed  $allowedScopes
     * @return void
     */
    public function __construct(
        $identifier,
        $name,
        $redirectUri,
        $isConfidential = false,
        $provider = null,
        $allowedScopes = null
    ) {
        $this->setIdentifier((string) $identifier);
        $this->setAllowedScopes($allowedScopes);

        $this->name = $name;
        $this->isConfidential = $isConfidential;
        $this->redirectUri = explode(',', $redirectUri);
        $this->provider = $provider;
    }

    /**
     * Get the client's identifier.
     *
     * @return string
     */
    public function getIdentifier()
    {
        return (string) $this->identifier;
    }

    /**
     * Set the client's identifier.
     *
     * @param  string  $identifier
     * @return void
     */
    public function setIdentifier($identifier)
    {
        $this->identifier = $identifier;
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

        $this->allowedScopes = array_map('trim', $this->allowedScopes);
    }
}
