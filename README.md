<p align="center">
&nbsp;
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

## Install

Require the package

```
composer require vizir/laravel-keycloak-web-guard
```

If you want to change user model or the routes, publish the config file (other configuration is done by `.env` file).

```
php artisan vendor:publish  --provider="Vizir\KeycloakWebGuard\KeycloakWebGuardServiceProvider"

```

## Configuration

Add to your `.env` file the follow values:

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

## API

We implement the `Illuminate\Contracts\Auth\Guard`. So, all Laravel default methods will be available.

Ex: `Auth::user()` returns the authenticated user.

## FAQ

### How to implement my Model?

You should extend `Vizir\KeycloakWebGuard\Models\KeycloakUser` and change the `user_model` configuration.
We'll ignore the `provider` config on `auth.php`.

If you set a model it not a child of `KeycloakUser` the application will provide a user.
Maybe a eloquent/database provider will work seamless, but we do not tested this case. 
If not, you should create a [UserProvider](https://laravel.com/docs/5.8/authentication#adding-custom-user-providers) to do the job: we use the `retrieveByCredentials` method passing the Keycloak Profile information to retrieve a instance of model.

### I cannot find my login form.

We register a `login` route to redirect to Keycloak Server. After login we'll receive and proccess the token to authenticate your user.

There's no login/registration form.

### How can I protect a route?

Just add the `keycloak-web` middleware:

```php
<?php 

// On RouteServiceProvider.php for example

Route::prefix('admin')
  ->middleware('keycloak-web')
  ->namespace($this->namespace)
  ->group(base_path('routes/web.php'));
  
// Or with Route facade in another place

Route::group(['middleware' => 'keycloak-web'], function () {
    Route::get('/protected', 'Controller@protected');
});
```

### Where the access token is persisted?

On session. We recommend implement the database driver.

### My client is not public.

If your client is not public, you should provide a `KEYCLOAK_CLIENT_SECRET` on your `.env`.

## Developers

* Mário Valney [@mariovalney](https://twitter.com/mariovalney)
* [Vizir Software Sutdio](https://vizir.com.br)
