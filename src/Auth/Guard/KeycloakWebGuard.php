<?php

namespace Vizir\KeycloakWebGuard\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Vizir\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Vizir\KeycloakWebGuard\Models\KeycloakUser;
use Vizir\KeycloakWebGuard\Facades\KeycloakWeb;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebGuard implements Guard
{
    /**
     * @var null|Authenticatable|KeycloakUser
     */
    protected $user;

    /**
     * Constructor.
     *
     * @param Request $request
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        return $this->user ?: $this->authenticate();
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @throws BadMethodCallException
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return false;
        }

        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        KeycloakWeb::saveToken($credentials);

        return $this->authenticate();
    }

    /**
     * Try to authenticate the user
     *
     * @throws KeycloakCallbackException
     * @return boolean
     */
    public function authenticate()
    {
        // Get Credentials
        $credentials = KeycloakWeb::retrieveToken();

        if (empty($credentials)) {
            return false;
        }

        $user = KeycloakWeb::getUserProfile($credentials);

        if (empty($user)) {
            KeycloakWeb::forgetToken();

            if (Config::get('app.debug', false)) {
                throw new KeycloakCallbackException('User cannot be authenticated.');
            }

            return false;
        }

        // Provide User
        $user = $this->provider->retrieveByCredentials($user);
        $this->setUser($user);

        return true;
    }

    /**
     * Check user is authenticated and has a role
     *
     * @param array|string $roles
     * @param string $resource Default is empty: point to client_id
     *
     * @return boolean
     */
    public function hasRole($roles, $resource = '')
    {
        if (empty($resource)) {
            $resource = Config::get('keycloak-web.client_id');
        }

        if (! $this->check()) {
            return false;
        }

        $token = KeycloakWeb::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = KeycloakWeb::parseAccessToken($token['access_token']);
        $resourceRoles = $token['resource_access'] ?? [];
        $resourceRoles = $resourceRoles[ $resource ] ?? [];
        $resourceRoles = $resourceRoles['roles'] ?? [];

        return empty(array_diff((array) $roles, $resourceRoles));
    }
}
