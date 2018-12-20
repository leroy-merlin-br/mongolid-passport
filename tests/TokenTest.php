<?php

use Illuminate\Container\Container;
use Mongolid\Container\Container as MongolidContainer;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    protected function setUp()
    {
        parent::setUp();
        MongolidContainer::setContainer(new Container());
    }

    public function test_token_can_determine_if_it_has_scopes()
    {
        $token = Laravel\Passport\Token::fill(['scopes' => ['user']]);

        $this->assertTrue($token->can('user'));
        $this->assertFalse($token->can('something'));
        $this->assertTrue($token->cant('something'));
        $this->assertFalse($token->cant('user'));

        $token = Laravel\Passport\Token::fill(['scopes' => ['*']]);
        $this->assertTrue($token->can('user'));
        $this->assertTrue($token->can('something'));
    }
}
