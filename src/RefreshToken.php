<?php
namespace Laravel\Passport;

use Mongolid\Laravel\AbstractModel as Model;

class RefreshToken extends Model
{
    /**
     * {@inheritdoc}
     */
    protected $collection = 'oauth_refresh_tokens';
}
