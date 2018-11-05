<?php

class TokenTest extends PHPUnit_Framework_TestCase
{
    public function test_token_can_determine_if_it_has_scopes()
    {
        $token = new Laravel\Passport\Token();
        $token->fill(['scopes' => ['user']]);

        $this->assertTrue($token->can('user'));
        $this->assertFalse($token->can('something'));
        $this->assertTrue($token->cant('something'));
        $this->assertFalse($token->cant('user'));

        $token = new Laravel\Passport\Token();
        $token->fill(['scopes' => ['*']]);
        $this->assertTrue($token->can('user'));
        $this->assertTrue($token->can('something'));
    }
}
