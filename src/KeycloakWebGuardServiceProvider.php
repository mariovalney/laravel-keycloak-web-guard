<?php

namespace Vizir\KeycloakWebGuard;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use Vizir\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;
use Vizir\KeycloakWebGuard\Services\KeycloakService;

class KeycloakWebGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Configuration
        $config = __DIR__ . '/../config/keycloak-web.php';

        $this->publishes([$config => config_path('keycloak-web.php')], 'config');
        $this->mergeConfigFrom($config, 'keycloak-web');
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        // Keycloak Web Guard
        Auth::extend('keycloak-web', function ($app, $name, array $config) {
            return new KeycloakWebGuard($app->request);
        });

        // Facades
        $this->app->bind('keycloak-web', function($app) {
            return $app->make(KeycloakService::class);
        });

        // Routes
        $this->registerRoutes();
    }

    /**
     * Register the authentication routes for keycloak.
     *
     * @return void
     */
    private function registerRoutes()
    {
        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'register' => 'register',
            'callback' => 'callback',
        ];

        $options = Config::get('keycloak-web.routes', []);
        $options = array_merge($defaults, $options);

        // Register Routes
        $router = $this->app->make('router');

        if (! empty($options['login'])) {
            $router->middleware('web')->get($options['login'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@login')->name('keycloak.login');
        }

        if (! empty($options['logout'])) {
            $router->middleware('web')->get($options['logout'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@logout')->name('keycloak.logout');
        }

        if (! empty($options['register'])) {
            $router->middleware('web')->get($options['register'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@register')->name('keycloak.register');
        }

        if (! empty($options['callback'])) {
            $router->middleware('web')->get($options['callback'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@callback')->name('keycloak.callback');
        }
    }
}
