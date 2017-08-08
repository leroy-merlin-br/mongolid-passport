<?php
namespace Laravel\Passport;

use MongolidLaravel\MongolidModel as Model;

class RefreshToken extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_refresh_tokens';
}
