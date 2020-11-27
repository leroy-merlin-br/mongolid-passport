<?php

use PHPUnit\Framework\TestCase;
use Laravel\Passport\Bridge\ClientRepository;

class BridgeClientRepositoryTest extends TestCase
{
    protected function setUp(): void
    {
        $clientModelRepository = Mockery::mock(Laravel\Passport\ClientRepository::class);
        $clientModelRepository->shouldReceive('findActive')->with(1)->andReturn(new BridgeClientRepositoryTestClientStub);

        $this->clientModelRepository = $clientModelRepository;
        $this->repository = new Laravel\Passport\Bridge\ClientRepository($clientModelRepository);
    }

    protected function tearDown(): void
    {
        Mockery::close();
    }

    public function test_can_get_client_for_auth_code_grant()
    {
        $client = $this->repository->getClientEntity(1, 'authorization_code', 'secret', true);

        $this->assertInstanceOf('Laravel\Passport\Bridge\Client', $client);
        $this->assertNull($this->repository->getClientEntity(1, 'authorization_code', 'wrong-secret', true));
        $this->assertNull($this->repository->getClientEntity(1, 'client_credentials', 'wrong-secret', true));
    }

    public function test_can_get_client_for_client_credentials_grant()
    {
        $client = $this->clientModelRepository->findActive(1);
        $client->personal_access_client = true;

        $this->assertInstanceOf('Laravel\Passport\Bridge\Client', $this->repository->getClientEntity(1, 'client_credentials', 'secret', true));
        $this->assertNull($this->repository->getClientEntity(1, 'authorization_code', 'secret', true));
    }

    public function test_password_grant_is_permitted()
    {
        $client = $this->clientModelRepository->findActive(1);
        $client->password_client = true;

        $this->assertInstanceOf('Laravel\Passport\Bridge\Client', $this->repository->getClientEntity(1, 'password', 'secret'));
    }

    public function test_password_grant_is_prevented()
    {
        $this->assertNull($this->repository->getClientEntity(1, 'password', 'secret'));
    }

    public function test_authorization_code_grant_is_permitted()
    {
        $this->assertInstanceOf('Laravel\Passport\Bridge\Client', $this->repository->getClientEntity(1, 'authorization_code', 'secret'));
    }

    public function test_authorization_code_grant_is_prevented()
    {
        $client = $this->clientModelRepository->findActive(1);
        $client->password_client = true;

        $this->assertNull($this->repository->getClientEntity(1, 'authorization_code', 'secret'));
    }

    public function test_personal_access_grant_is_permitted()
    {
        $client = $this->clientModelRepository->findActive(1);
        $client->personal_access_client = true;

        $this->assertInstanceOf('Laravel\Passport\Bridge\Client', $this->repository->getClientEntity(1, 'personal_access', 'secret'));
    }

    public function test_personal_access_grant_is_prevented()
    {
        $this->assertNull($this->repository->getClientEntity(1, 'personal_access', 'secret'));
    }

    public function test_client_credentials_grant_is_permitted()
    {
        $this->assertInstanceOf('Laravel\Passport\Bridge\Client', $this->repository->getClientEntity(1, 'client_credentials', 'secret'));
    }

    public function test_client_credentials_grant_is_prevented()
    {
        $client = $this->clientModelRepository->findActive(1);
        $client->secret = null;

        $this->assertNull($this->repository->getClientEntity(1, 'client_credentials', 'secret'));
    }

    public function test_grant_types_allows_request()
    {
        $client = $this->clientModelRepository->findActive(1);
        $client->grant_types = ['client_credentials'];

        $this->assertInstanceOf('Laravel\Passport\Bridge\Client', $this->repository->getClientEntity(1, 'client_credentials', 'secret'));
    }

    public function test_grant_types_disallows_request()
    {
        $client = $this->clientModelRepository->findActive(1);
        $client->grant_types = ['client_credentials'];

        $this->assertNull($this->repository->getClientEntity(1, 'authorization_code', 'secret'));
    }

    public function test_should_get_client_with_allowed_scopes()
    {
        $clients = Mockery::mock('Laravel\Passport\ClientRepository');
        $client = new BridgeClientRepositoryTestClientStub;
        $client->allowed_scopes = 'foo,bar';
        $clients->shouldReceive('findActive')->with(1)->andReturn($client);
        $repository = new ClientRepository($clients);

        $client = $repository->getClientEntity(1, 'client_credentials', 'secret', true);

        $this->assertSame(['foo', 'bar'], $client->getAllowedScopes());
    }

    public function test_should_get_client_with_allowed_scopes_as_array()
    {
        $clients = Mockery::mock('Laravel\Passport\ClientRepository');
        $client = new BridgeClientRepositoryTestClientStub;
        $client->allowed_scopes = ['foo', 'bar'];
        $clients->shouldReceive('findActive')->with(1)->andReturn($client);
        $repository = new ClientRepository($clients);

        $client = $repository->getClientEntity(1, 'client_credentials', 'secret', true);

        $this->assertSame(['foo', 'bar'], $client->getAllowedScopes());
    }

    public function test_should_restrict_scopes_for_client_with_wild_card()
    {
        $clients = Mockery::mock('Laravel\Passport\ClientRepository');
        $client = new BridgeClientRepositoryTestClientStub;
        $client->allowed_scopes = '*';
        $clients->shouldReceive('findActive')->with(1)->andReturn($client);
        $repository = new ClientRepository($clients);

        $client = $repository->getClientEntity(1, 'client_credentials', 'secret', true);

        $this->assertSame(['*'], $client->getAllowedScopes());
    }
}

class BridgeClientRepositoryTestClientStub
{
    public $name = 'Client';
    public $redirect = 'http://localhost';
    public $secret = 'secret';
    public $personal_access_client = false;
    public $password_client = false;
    public $allowed_scopes = null; // @todo Check if it is necessary this property
    public $grant_types;

    public function firstParty()
    {
        return $this->personal_access_client || $this->password_client;
    }
}
