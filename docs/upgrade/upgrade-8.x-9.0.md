## Upgrading To 9.0 From 8.x

### Support For Multiple Guards

PR: https://github.com/laravel/passport/pull/1220

Passport now has support for multiple guard user providers. Because of this change, you must add a `provider` column to the `oauth_clients` database table:

If you have not previously published the Passport migrations, you should manually add the `provider` column to your database.

### Client Credentials Secret Hashing

PR: https://github.com/laravel/passport/pull/1145

Client secrets may now be stored using a Bcrypt hash. However, before enabling this functionality, please consider the following. First, there is no way to reverse the hashing process once you have migrated your existing tokens. Secondly, when hashing client secrets, you will only have one opportunity to display the plain-text value to the user before it is hashed and stored in the database.

#### Personal Access Clients

Before you continue, you should set your personal access client ID and unhashed secret in your `.env` file:

    PASSPORT_PERSONAL_ACCESS_CLIENT_ID=client-id-value
    PASSPORT_PERSONAL_ACCESS_CLIENT_SECRET=unhashed-client-secret-value

Next, you should register these values by placing the following calls within the `boot` method of your `AppServiceProvider`:

    Passport::personalAccessClientId(config('passport.personal_access_client.id'));
    Passport::personalAccessClientSecret(config('passport.personal_access_client.secret'));

> Make sure you follow the instructions above before hashing your secrets. Otherwise, irreversible data loss may occur.

#### Hashing Existing Secrets

You may enable client secret hashing by calling the `Passport::hashClientSecrets()` method within the `boot` method of your `AppServiceProvider`. For convenience, we've included a new Artisan command which you can run to hash all existing client secrets:

    php artisan passport:hash

**Again, please be aware that running this command cannot be undone. For extra precaution, you may wish to create a backup of your database before running the command.**

### Client Credentials Middleware Changes

PR: https://github.com/laravel/passport/pull/1132

[After a lengthy debate](https://github.com/laravel/passport/issues/1125), it was decided to revert the change made [in a previous PR](https://github.com/laravel/passport/pull/1040) that introduced an exception when the client credentials middleware was used to authenticate first party clients.

### Switch From `getKey` To `getAuthIdentifier`

PR: https://github.com/laravel/passport/pull/1134

Internally, Passport will now use the `getAuthIdentifier` method to determine a model's primary key. This is consistent with the framework and Laravel's first party libraries.

### Remove Deprecated Functionality

PR: https://github.com/laravel/passport/pull/1235

The deprecated `revokeOtherTokens` and `pruneRevokedTokens` methods and the `revokeOtherTokens` and `pruneRevokedTokens` properties were removed from the `Passport` object.
