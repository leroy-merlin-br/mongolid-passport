<?php

namespace Laravel\Passport;

use Illuminate\Support\Str;
use MongoDB\BSON\ObjectId;
use RuntimeException;

class ClientRepository
{
    /**
     * The personal access client ID.
     *
     * @var int|string|null
     */
    protected $personalAccessClientId;

    /**
     * The personal access client secret.
     *
     * @var string|null
     */
    protected $personalAccessClientSecret;

    /**
     * Create a new client repository.
     *
     * @param  int|string|null  $personalAccessClientId
     * @param  string|null  $personalAccessClientSecret
     * @return void
     */
    public function __construct($personalAccessClientId = null, $personalAccessClientSecret = null)
    {
        $this->personalAccessClientId = $personalAccessClientId;
        $this->personalAccessClientSecret = $personalAccessClientSecret;
    }

    /**
     * Get a client by the given ID.
     *
     * @param  string|ObjectId $id
     *
     * @return \Laravel\Passport\Client|null
     */
    public function find($id)
    {
        $clientModel = Passport::clientModel();

        return $clientModel::first($id);
    }

    /**
     * Get an active client by the given ID.
     *
     * @param string|ObjectId $id
     *
     * @return \Laravel\Passport\Client|null
     */
    public function findActive($id)
    {
        $client = $this->find($id);

        return $client && ! $client->revoked ? $client : null;
    }

    /**
     * Get a client instance for the given ID and user ID.
     *
     * @param  string|ObjectId  $clientId
     * @param  mixed            $userId
     *
     * @return \Laravel\Passport\Client|null
     */
    public function findForUser($clientId, $userId)
    {
        $clientModel = Passport::clientModel();

        return $clientModel::first(['_id' => (string) $clientId, 'user_id' => (string) $userId]);
    }

    /**
     * Get the client instances for the given user ID.
     *
     * @param  mixed $userId
     *
     * @return \Mongolid\Cursor\CursorInterface
     */
    public function forUser($userId)
    {
        $clientModel = Passport::clientModel();

        return $clientModel::where(['user_id' => (string) $userId])
            ->sort(['name' => 1]);
    }

    /**
     * Get the active client instances for the given user ID.
     *
     * @param  mixed $userId
     *
     * @return \Illuminate\Support\Collection
     */
    public function activeForUser($userId)
    {
        return collect($this->forUser($userId))->reject(
            function ($client) {
                return (bool) $client->revoked;
            }
        )->map(
            function ($client) {
                return $client->toArray();
            }
        )->values();
    }

    /**
     * Get the personal access token client for the application.
     *
     * @return \Laravel\Passport\Client
     *
     * @throws \RuntimeException
     */
    public function personalAccessClient()
    {
        if ($this->personalAccessClientId) {
            return $this->find($this->personalAccessClientId);
        }

        $client = Passport::personalAccessClient();

        if (! $client->first()) {
            throw new RuntimeException('Personal access client not found. Please create one.');
        }

        return $client->all()
            ->sort(['created_at' => -1])
            ->first()
            ->client();
    }

    /**
     * Store a new client.
     *
     * @param  string|ObjectId  $userId
     * @param  string           $name
     * @param  string           $redirect
     * @param  string|null      $provider
     * @param  bool             $personalAccess
     * @param  bool             $password
     * @param  bool             $confidential
     * @param  string           $allowedScopes
     *
     * @return \Laravel\Passport\Client
     */
    public function create($userId, $name, $redirect, $provider = null, $personalAccess = false, $password = false, $confidential = true, $allowedScopes = null)
    {
        $client = Passport::client();

        $client->fill(
            [
                'user_id' => $userId,
                'name' => $name,
                'secret' => ($confidential || $personalAccess) ? Str::random(40) : null,
                'provider' => $provider,
                'redirect' => $redirect,
                'personal_access_client' => $personalAccess,
                'password_client' => $password,
                'revoked' => false,
                'allowed_scopes' => $allowedScopes,
            ],
            true
        );

        $client->save();

        return $client;
    }

    /**
     * Store a new personal access token client.
     *
     * @param  string|ObjectId  $userId
     * @param  string           $name
     * @param  string           $redirect
     *
     * @return \Laravel\Passport\Client
     */
    public function createPersonalAccessClient($userId, $name, $redirect)
    {
        return tap($this->create($userId, $name, $redirect, null, true), function ($client) {
            $accessClient = Passport::personalAccessClient();
            $accessClient->client_id = $client->_id;
            $accessClient->save();
        });
    }

    /**
     * Store a new password grant client.
     *
     * @param  string|ObjectId  $userId
     * @param  string           $name
     * @param  string           $redirect
     * @param  string|null      $provider
     *
     * @return \Laravel\Passport\Client
     */
    public function createPasswordGrantClient($userId, $name, $redirect, $provider = null)
    {
        return $this->create($userId, $name, $redirect, $provider, false, true);
    }

    /**
     * Update the given client.
     *
     * @param  Client $client
     * @param  string $name
     * @param  string $redirect
     *
     * @return \Laravel\Passport\Client
     */
    public function update(Client $client, $name, $redirect)
    {
        $client->fill(
            [
                'name' => $name,
                'redirect' => $redirect,
            ],
            true
        );

        $client->save();

        return $client;
    }

    /**
     * Regenerate the client secret.
     *
     * @param  \Laravel\Passport\Client $client
     *
     * @return \Laravel\Passport\Client
     */
    public function regenerateSecret(Client $client)
    {
        $client->fill(
            [
                'secret' => Str::random(40),
            ],
            true
        );

        $client->save();

        return $client;
    }

    /**
     * Determine if the given client is revoked.
     *
     * @param  string|ObjectId $id
     *
     * @return bool
     */
    public function revoked($id)
    {
        $client = $this->find($id);

        return is_null($client) || $client->revoked;
    }

    /**
     * Delete the given client.
     *
     * @param \Laravel\Passport\Client $client
     *
     * @return void
     */
    public function delete(Client $client)
    {
        foreach($client->tokens() as $token) {
            $token->revoke();
        }

        $client->revoked = true;
        $client->update();
    }

    /**
     * Get the personal access client id.
     *
     * @return int|string|null
     */
    public function getPersonalAccessClientId()
    {
        return $this->personalAccessClientId;
    }

    /**
     * Get the personal access client secret.
     *
     * @return string|null
     */
    public function getPersonalAccessClientSecret()
    {
        return $this->personalAccessClientSecret;
    }
}
