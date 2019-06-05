<?php

namespace Vizir\KeycloakWebGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static getLoginUrl()
 * @method static getLogoutUrl()
 * @method static getAccessToken(string $code)
 * @method static getUserProfile(array $credentials)
 * @method static forgetToken()
 * @method static routes(array $options=[])
 */
class KeycloakWeb extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'keycloak-web';
    }

    /**
     * Register the authentication routes for keycloak.
     *
     * @param  array  $options
     * @return void
     */
    public static function routes(array $options = [])
    {
        $router = static::$app->make('router');

        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'callback' => 'callback',
        ];

        $options = array_merge($defaults, $options);

        if (! empty($options['login'])) {
            $router->get($options['login'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@login')->name('keycloak.login');
        }

        if (! empty($options['logout'])) {
            $router->get($options['logout'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@logout')->name('keycloak.logout');
        }

        if (! empty($options['callback'])) {
            $router->get($options['callback'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@callback')->name('keycloak.callback');
        }
    }
}
