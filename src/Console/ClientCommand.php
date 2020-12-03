<?php

namespace Laravel\Passport\Console;

use Laravel\Passport\Passport;
use Illuminate\Console\Command;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;

class ClientCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'passport:client
            {--personal : Create a personal access token client}
            {--password : Create a password grant client}
            {--client : Create a client credentials grant client}
            {--name= : The name of the client}
            {--redirect_uri= : The URI to redirect to after authorization }
            {--user_id= : The user ID the client should be assigned to }
            {--public : Create a public client (Auth code grant type only) }';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create a client for issuing access tokens';

    /**
     * Execute the console command.
     *
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @return void
     */
    public function handle(ClientRepository $clients)
    {
        if ($this->option('personal')) {
            $this->createPersonalClient($clients);
        } elseif ($this->option('password')) {
            $this->createPasswordClient($clients);
        } elseif ($this->option('client')) {
            $this->createClientCredentialsClient($clients);
        } else {
            $this->createAuthCodeClient($clients);
        }
    }

    /**
     * Create a new personal access client.
     *
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @return void
     */
    protected function createPersonalClient(ClientRepository $clients)
    {
        $name = $this->option('name') ?: $this->ask(
            'What should we name the personal access client?',
            config('app.name').' Personal Access Client'
        );

        $client = $clients->createPersonalAccessClient(
            null, $name, 'http://localhost'
        );

        $this->info('Personal access client created successfully.');

        $this->outputClientDetails($client);
    }

    /**
     * Create a new password grant client.
     *
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @return void
     */
    protected function createPasswordClient(ClientRepository $clients)
    {
        $name = $this->option('name') ?: $this->ask(
            'What should we name the password grant client?',
            config('app.name').' Password Grant Client'
        );

        $client = $clients->createPasswordGrantClient(
            null, $name, 'http://localhost'
        );

        $this->info('Password grant client created successfully.');

        $this->outputClientDetails($client);
    }

    /**
     * Create a client credentials grant client.
     *
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @return void
     */
    protected function createClientCredentialsClient(ClientRepository $clients)
    {
        $name = $this->option('name') ?: $this->ask(
            'What should we name the client?',
            config('app.name').' ClientCredentials Grant Client'
        );

        $this->line('Available scopes:');
        $this->table(['id', 'description'], Passport::scopes()->toArray());

        do {
            $allowedScopes = $this->ask(
                'Which scopes does the client need? Valid options: all / none / [comma separated scopes]',
                'none'
            );
        } while (false === $allowedScopes = $this->parseAllowedScopes($allowedScopes));

        $client = $clients->create(
            null, $name, '', false, false, true, $allowedScopes
        );

        $this->info('New client created successfully.');

        $this->outputClientDetails($client);
    }

    /**
     * Create a authorization code client.
     *
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @return void
     */
    protected function createAuthCodeClient(ClientRepository $clients)
    {
        $userId = $this->option('user_id') ?: $this->ask(
            'Which user ID should the client be assigned to?'
        );

        $name = $this->option('name') ?: $this->ask(
            'What should we name the client?'
        );

        $redirect = $this->option('redirect_uri') ?: $this->ask(
            'Where should we redirect the request after authorization?',
            url('/auth/callback')
        );

        $allowedScopes = config('auth.authorization_code.allowed_scopes');

        $client = $clients->create(
            $userId, $name, $redirect, false, false, ! $this->option('public'), $allowedScopes
        );

        $this->info('New client created successfully.');

        $this->outputClientDetails($client);
    }

    /**
     * Output the client's ID and secret key.
     *
     * @param  \Laravel\Passport\Client  $client
     * @return void
     */
    protected function outputClientDetails(Client $client)
    {
        $this->line('<comment>Client ID:</comment> '.$client->_id);
        $this->line('<comment>Client secret:</comment> '.$client->secret);
    }

    /**
     * Get available scopes keys as string.
     *
     * @return string
     */
    protected function getAvailableScopes()
    {
        $scopes = [];

        foreach (Passport::scopes() as $scope) {
            $scopes[] = $scope->_id;
        }

        return implode(',', $scopes);
    }

    /**
     * Check if allowed scopes option is valid.
     *
     * @param string $allowedScopes
     *
     * @return string|bool
     */
    protected function parseAllowedScopes($allowedScopes)
    {
        if ('all' === $allowedScopes) {
            return '*';
        }

        if ('none' === $allowedScopes) {
            return null;
        }

        if (!empty($allowedScopes)) {
            $scopes = explode(',', $allowedScopes);

            foreach ($scopes as $scope) {
                $scope = trim($scope);
                if (!Passport::hasScope($scope)) {
                    $this->warn("Invalid scope option {$scope}.");

                    return false;
                }
            }

            return $allowedScopes;
        }

        $this->warn('Invalid scope option.');

        return false;
    }
}
