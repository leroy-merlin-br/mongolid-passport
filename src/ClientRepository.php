<?php

namespace Laravel\Passport;

class ClientRepository
{
    /**
     * Get a client by the given ID.
     *
     * @param  int $id
     *
     * @return \Laravel\Passport\Client|null
     */
    public function find($id)
    {
        return Client::first($id);
    }

    /**
     * Get an active client by the given ID.
     *
     * @param string|int $id
     *
     * @return \Laravel\Passport\Client|null
     */
    public function findActive($id)
    {
        $client = $this->find($id);

        return $client && !$client->revoked ? $client : null;
    }

    /**
     * Get a client instance for the given ID and user ID.
     *
     * @param  int   $clientId
     * @param  mixed $userId
     *
     * @return \Laravel\Passport\Client|null
     */
    public function findForUser($clientId, $userId)
    {
        return Client::first(['_id' => (string) $clientId, 'user_id' => (string) $userId]);
    }

    /**
     * Get the client instances for the given user ID.
     *
     * @param  mixed $userId
     *
     * @return \Mongolid\Cursor\Cursor
     */
    public function forUser($userId)
    {
        return Client::where(['user_id' => (string) $userId])
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
     */
    public function personalAccessClient()
    {
        if (Passport::$personalAccessClient) {
            return $this->find(Passport::$personalAccessClient);
        }

        return PersonalAccessClient::all()
            ->sort(['created_at' => -1])
            ->first()
            ->client();
    }

    /**
     * Store a new client.
     *
     * @param  int    $userId
     * @param  string $name
     * @param  string $redirect
     * @param  bool   $personalAccess
     * @param  bool   $password
     * @param  string $allowedScopes
     *
     * @return \Laravel\Passport\Client
     */
    public function create($userId, $name, $redirect, $personalAccess = false, $password = false, $allowedScopes = null)
    {
        $client = new Client();

        $client->fill(
            [
                'user_id' => $userId,
                'name' => $name,
                'secret' => str_random(40),
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
     * @param  int    $userId
     * @param  string $name
     * @param  string $redirect
     *
     * @return \Laravel\Passport\Client
     */
    public function createPersonalAccessClient($userId, $name, $redirect)
    {
        return $this->create($userId, $name, $redirect, true);
    }

    /**
     * Store a new password grant client.
     *
     * @param  int    $userId
     * @param  string $name
     * @param  string $redirect
     *
     * @return \Laravel\Passport\Client
     */
    public function createPasswordGrantClient($userId, $name, $redirect)
    {
        return $this->create($userId, $name, $redirect, false, true);
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
                'secret' => str_random(40),
            ],
            true
        );

        $client->save();

        return $client;
    }

    /**
     * Determine if the given client is revoked.
     *
     * @param  int $id
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
            $token->revoked = true;
            $token->update();
        }

        $client->revoked = true;
        $client->update();
    }
}
