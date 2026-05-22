<?php

namespace Laravel\Passport\Events;

class AccessTokenRevoked
{
    /**
     * The revoked token ID.
     *
     * @var string
     */
    public $tokenId;

    /**
     * Create a new event instance.
     *
     * @param  string  $tokenId
     * @return void
     */
    public function __construct($tokenId)
    {
        $this->tokenId = $tokenId;
    }
}

