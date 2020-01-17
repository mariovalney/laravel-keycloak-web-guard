<p align="center">
    <img src="https://img.shields.io/packagist/v/vizir/laravel-keycloak-web-guard.svg" />
    <img src="https://img.shields.io/packagist/dt/vizir/laravel-keycloak-web-guard.svg" />
</p>

# Keycloak Web Guard for Laravel

This packages allow you authenticate users with [Keycloak Server](https://www.keycloak.org).

It works on front. For APIs we recommend [laravel-keycloak-guard](https://github.com/robsontenorio/laravel-keycloak-guard).

## Requirements

* Have a Keycloak Server.
* Have a realm configured and a client that accepts authentication.

## The flow

1. User access a guarded route and is redirected to Keycloak login.
1. User signin and obtains a code.
1. He's redirected to callback page and we change the code for a access token.
1. We store it on session and validate user.
1. User is logged.
1. We redirect the user to "redirect_url" route (see config) or the intended one.

## Install

Require the package

```
composer require vizir/laravel-keycloak-web-guard
```

If you want to change routes or the default values for Keycloak, publish the config file:

```
php artisan vendor:publish  --provider="Vizir\KeycloakWebGuard\KeycloakWebGuardServiceProvider"

```

## Configuration

After publishing `config/keycloak-web.php` file, you can change the routes:

```php
'redirect_url' => '/admin',

'routes' => [
    'login' => 'login',
    'logout' => 'logout',
    'register' => 'register',
    'callback' => 'callback',
]
```

Change any value to change the URL.

Other configurations can be changed to have a new default value, but we recommend to use `.env` file:

*  `KEYCLOAK_BASE_URL`

The Keycloak Server url. Generally is something like: `https://your-domain.com/auth`.

*  `KEYCLOAK_REALM`

The Keycloak realm. The default is `master`.

*  `KEYCLOAK_REALM_PUBLIC_KEY`

The Keycloak Server realm public key (string).

In dashboard go to: Keycloak >> Realm Settings >> Keys >> RS256 >> Public Key.

*  `KEYCLOAK_CLIENT_ID`

Keycloak Client ID.

In dashboard go to: Keycloak >> Clients >> Installation.

*  `KEYCLOAK_CLIENT_SECRET`

Keycloak Client Secret. If empty we'll not send it to Token Endpoint.

In dashboard go to: Keycloak >> Clients >> Installation.

*  `KEYCLOAK_CACHE_OPENID`

We can cache the OpenId Configuration: it's a list of endpoints we require to Keycloak.

If you activate it, *remember to flush the cache* when change the realm or url.

## Laravel Auth

You should add Keycloak Web guard to your `config/auth.php`.

Just add **keycloak-web** to "driver" option on configurations you want.

As my default is web, I add to it:

```php
'guards' => [
    'web' => [
        'driver' => 'keycloak-web',
        'provider' => 'users',
    ],

    // ...
],
```

And change your provider config too:

```php
'providers' => [
    'users' => [
        'driver' => 'keycloak-users',
        'model' => Vizir\KeycloakWebGuard\Models\KeycloakUser::class,
    ],

    // ...
]
```

**Note:** if you want use another User Model, check the FAQ *How to implement my Model?*.

## API

We implement the `Illuminate\Contracts\Auth\Guard`. So, all Laravel default methods will be available.

Ex: `Auth::user()` returns the authenticated user.

## Roles

You can check user has a role simply by `Auth::hasRole('role')`;

This method accept two parameters: the first is the role (string or array of strings) and the second is the resource.

If not provided, resource will be the client_id, which is the regular check if you authenticating into this client to your front.

### Keycloak Can Middleware

You can check user against one or more roles using the `keycloak-web-can` Middleware.

Add this to your Controller's `__construct` method:

```php
$this->middleware('keycloak-web-can:manage-something-cool');

// For multiple roles, separate with '|'
$this->middleware('keycloak-web-can:manage-something-cool|manage-something-nice|manage-my-application');
```

This middleware works searching for all roles on default resource (client_id). You can extend it and register your own middleware on Kernel.php or just use `Auth::hasRole($roles, $resource)` on your Controller.

## FAQ

### How to implement my Model?

We registered a new user provider that you configured on `config/auth.php` called "keycloak-users".

In this same configuration you setted the model. So you can register your own model extending `Vizir\KeycloakWebGuard\Models\KeycloakUser` class and changing this configuration.

You can implement your own [User Provider](https://laravel.com/docs/5.8/authentication#adding-custom-user-providers): just remember to implement the `retrieveByCredentials` method receiving the Keycloak Profile information to retrieve a instance of model.

Eloquent/Database User Provider should work well as they will parse the Keycloak Profile and make a "where" to your database. So your user data must match with Keycloak Profile.

### I cannot find my login form.

We register a `login` route to redirect to Keycloak Server. After login we'll receive and proccess the token to authenticate your user.

There's no login/registration form.

### How can I protect a route?

Just add the `keycloak-web` middleware:

```php
// On RouteServiceProvider.php for example

Route::prefix('admin')
  ->middleware('keycloak-web')
  ->namespace($this->namespace)
  ->group(base_path('routes/web.php'));

// Or with Route facade in another place

Route::group(['middleware' => 'keycloak-web'], function () {
    Route::get('/admin', 'Controller@admin');
});
```

### Where the access token is persisted?

On session. We recommend implement the database driver if you have load balance.

### I'm having problems with session (stuck on login loop)

For some reason Laravel can present a problem with EncryptCookies middleware changing the session ID.

In this case, we will always try to login, as tokens cannot be retrieved.

You can remove session_id cooki from encryption:

```php
// On your EncryptCookies middleware

class EncryptCookies extends Middleware
{
    protected $except = [];

    public function __construct(EncrypterContract $encrypter)
    {
        parent::__construct($encrypter);

        /**
         * This will disable in runtime.
         *
         * If you have a "session.cookie" option or don't care about changing the app name
         * (in another environment, for example), you can only add it to "$except" array on top
         */
        $this->disableFor(config('session.cookie'));
    }
}

```

### My client is not public.

If your client is not public, you should provide a `KEYCLOAK_CLIENT_SECRET` on your `.env`.

## Developers

* Mário Valney [@mariovalney](https://twitter.com/mariovalney)
* [Vizir Software Sutdio](https://vizir.com.br)
