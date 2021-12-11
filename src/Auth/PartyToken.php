<?php

namespace Vizir\KeycloakWebGuard\Auth;

class PartyToken
{
    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var string
     */
    protected $refreshToken;

    /**
     * @var int
     */
    protected $expires;

    /**
     * Constructs an request party token.
     *
     * @param array $data The token from Keycloak as array.
     */
    public function __construct($data = [])
    {
        $data = (array) $data;

        if (! empty($data['access_token'])) {
            $this->accessToken = $data['access_token'];
        }

        if (! empty($data['refresh_token'])) {
            $this->refreshToken = $data['refresh_token'];
        }

        if (! empty($data['expires_in'])) {
            $this->expires = (int) $data['expires_in'];
        }
    }

    /**
     * Get AccessToken
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Get RefreshToken
     *
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Check access token has expired
     *
     * @return boolean
     */
    public function hasExpired()
    {
        $exp = $this->parseAccessToken();
        $exp = $exp['exp'] ?? '';

        return time() >= (int) $exp;
    }

    /**
     * Parse the Access Token
     *
     * @return array
     */
    public function parseAccessToken()
    {
        return $this->parseToken($this->accessToken);
    }

    /**
     * Get token (access/refresh/id) data
     *
     * @param string $token
     * @return array
     */
    protected function parseToken($token)
    {
        if (! is_string($token)) {
            return [];
        }

        $token = explode('.', $token);
        $token = $this->base64UrlDecode($token[1]);

        return json_decode($token, true);
    }

    /**
     * Base64UrlDecode string
     *
     * @link https://www.php.net/manual/pt_BR/function.base64-encode.php#103849
     *
     * @param  string $data
     * @return string
     */
    protected function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
