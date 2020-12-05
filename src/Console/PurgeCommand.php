<?php

namespace Laravel\Passport\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Laravel\Passport\AuthCode;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use MongoDB\BSON\UTCDateTime;

class PurgeCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'passport:purge
                            {--revoked : Only purge revoked tokens and authentication codes}
                            {--expired : Only purge expired tokens and authentication codes}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Purge revoked and / or expired tokens and authentication codes';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $expired = new UTCDateTime(Carbon::now()->subDays(7));

        if (($this->option('revoked') && $this->option('expired')) ||
            (! $this->option('revoked') && ! $this->option('expired'))) {
            Token::where(['$or' => ['revoked' => true, 'expires_at' => ['$lt', $expired]]])->delete();
            AuthCode::where(['$or' => ['revoked' => true, 'expires_at' => ['$lt', $expired]]])->delete();
            RefreshToken::where(['$or' => ['revoked' => true, 'expires_at' => ['$lt', $expired]]])->delete();

            $this->info('Purged revoked items and items expired for more than seven days.');
        } elseif ($this->option('revoked')) {
            Token::where(['revoked' => true])->delete();
            AuthCode::where(['revoked' => true])->delete();
            RefreshToken::where(['revoked' => true])->delete();

            $this->info('Purged revoked items.');
        } elseif ($this->option('expired')) {
            Token::where(['expires_at' => ['$lt' => $expired]])->delete();
            AuthCode::where(['expires_at' => ['$lt' => $expired]])->delete();
            RefreshToken::where(['expires_at' => ['$lt' => $expired]])->delete();

            $this->info('Purged items expired for more than seven days.');
        }
    }
}
