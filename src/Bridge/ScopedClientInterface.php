<?php

namespace Laravel\Passport\Bridge;

use League\OAuth2\Server\Entities\ClientEntityInterface;

interface ScopedClientInterface extends ClientEntityInterface
{
    /**
     * Get the client's allowed scopes.
     *
     * @return array
     */
    public function getAllowedScopes();
}
