## Upgrading To 10.0 From 9.x

### Minimum PHP Version

PHP 7.3 is now the minimum required version.

### Minimum Laravel Version

Laravel 8.0 is now the minimum required version.

### Old Static Personal Client Methods Removed

PR: https://github.com/laravel/passport/pull/1325

The personal client configuration methods have been removed from the `Passport` class since they are no longer necessary. You should remove calls to these methods from your `AuthServiceProvider`.
