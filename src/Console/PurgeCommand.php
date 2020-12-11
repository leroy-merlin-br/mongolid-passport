<?php

namespace Laravel\Passport\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Laravel\Passport\Passport;
use MongoDB\BSON\UTCDateTime;
use Mongolid\Cursor\Cursor;

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
        $query = [];
        $message = '';

        if (($this->option('revoked') && $this->option('expired')) ||
            (! $this->option('revoked') && ! $this->option('expired'))) {
            $query = ['$or' => [['revoked' => true], ['expires_at' => ['$lt' => $expired]]]];
            $message = 'Purged revoked items and items expired for more than seven days.';
        } elseif ($this->option('revoked')) {
            $query = ['revoked' => true];
            $message = 'Purged revoked items.';
        } elseif ($this->option('expired')) {
            $query = ['expires_at' => ['$lt' => $expired]];
            $message = 'Purged items expired for more than seven days.';
        }

        if ($tokens = Passport::tokenModel()::where($query)) {
            $this->purgeTokens($tokens);
        }

        if ($authCodes = Passport::authCodeModel()::where($query)) {
            $this->purgeTokens($authCodes);
        }

        if ($refreshTokens = Passport::refreshTokenModel()::where($query)) {
            $this->purgeTokens($refreshTokens);
        }

        $this->info($message);
    }

    protected function purgeTokens(Cursor $tokens)
    {
        foreach ($tokens as $token) {
            $token->delete();
        }
    }
}
