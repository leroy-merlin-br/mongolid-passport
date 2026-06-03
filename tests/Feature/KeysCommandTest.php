<?php

namespace Laravel\Passport\Tests\Feature;

class KeysCommandTest extends PassportTestCase
{
    protected function tearDown(): void
    {
        @unlink(self::PUBLIC_KEY);
        @unlink(self::PRIVATE_KEY);

        parent::tearDown();
    }

    public function testPrivateAndPublicKeysAreGenerated()
    {
        $this->assertFileExists(self::PUBLIC_KEY);
        $this->assertFileExists(self::PRIVATE_KEY);
    }

    public function testPrivateAndPublicKeysShouldNotBeGeneratedTwice()
    {
        $this->artisan('passport:keys')
            ->assertFailed()
            ->expectsOutputToContain('Encryption keys already exist. Use the --force option to overwrite them.');
    }
}
