<?php

namespace Vizir\KeycloakWebGuard\Models;

use Illuminate\Contracts\Auth\Authenticatable;

class KeycloakUser implements Authenticatable
{
    /**
     * Attributes we retrieve from Profile
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email'
    ];

    /**
     * User attributes
     *
     * @var array
     */
    protected $attributes = [];

    /**
     * Constructor
     *
     * @param array $profile Keycloak user info
     */
    public function __construct(array $profile)
    {
        foreach ($profile as $key => $value) {
            if (in_array($key, $this->fillable)) {
                $this->attributes[ $key ] = $value;
            }
        }
    }

    /**
     * Magic method to get attributes
     *
     * @param  string $name
     * @return mixed
     */
    public function __get(string $name)
    {
        return $this->attributes[ $name ] ?? null;
    }

    /**
     * Get User Gravatar
     *
     * @return string
     */
    public function getAvatar()
    {
        $hash = md5($this->email);
        return 'https://www.gravatar.com/avatar/' . $hash;
    }

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return 'email';
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->email;
    }

    /**
     * Get the password for the user.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getAuthPassword()
    {
        throw new \BadMethodCallException('Unexpected method call');
    }

    /**
     * Get the token value for the "remember me" session.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberToken()
    {
        throw new \BadMethodCallException('Unexpected method call');
    }

    /**
     * Set the token value for the "remember me" session.
     *
     * @param string $value
     * @codeCoverageIgnore
     */
    public function setRememberToken($value)
    {
        throw new \BadMethodCallException('Unexpected method call');
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberTokenName()
    {
        throw new \BadMethodCallException('Unexpected method call');
    }
}
