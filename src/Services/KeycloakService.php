<?php

namespace Vizir\KeycloakWebGuard\Services;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Vizir\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;

class KeycloakService
{
    /**
     * The Session key for token
     */
    const KEYCLOAK_SESSION = '_keycloak_token';

    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @param ClientInterface $client
     * @return void
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(Config::get('keycloak-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = Config::get('keycloak-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = Config::get('keycloak-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = Config::get('keycloak-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = Config::get('keycloak-web.cache_openid', false);
        }

        $this->httpClient = $client;
        $this->openid = $this->getOpenIdConfiguration();
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl()
    {
        $url = $this->openid['authorization_endpoint'];
        $params = [
            'scope' => 'openid',
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => route('keycloak.callback'),
            'state' => csrf_token(),
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = $this->openid['end_session_endpoint'];

        if (! Route::has('index')) {
            return $url;
        }

        return $this->buildUrl($url, ['redirect_uri' => route('index')]);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getRegisterUrl()
    {
        $url = $this->openid['authorization_endpoint'];
        $url = preg_replace('/\/auth$/', '/registrations', $url);

        if (! Route::has('index')) {
            return $url;
        }

        return $this->buildUrl($url, ['redirect_uri' => route('index')]);
    }

    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url = $this->openid['token_endpoint'];
        $params = [
            'code' => $code,
            'client_id' => $this->clientId,
            'grant_type' => 'authorization_code',
            'redirect_uri' => route('keycloak.callback'),
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = $this->openid['token_endpoint'];
        $params = [
            'client_id' => $this->clientId,
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => route('keycloak.callback'),
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Get access token from Code
     * @param  array $credentials
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);

        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['id_token'])) {
            $this->forgetToken();
            return [];
        }

        $url = $this->openid['userinfo_endpoint'];
        $headers = [
            'Authorization' => 'Bearer ' . $credentials['access_token'],
            'Accept' => 'application/json',
        ];

        $user = [];

        try {
            $response = $this->httpClient->request('GET', $url, ['headers' => $headers]);


            if ($response->getStatusCode() === 200) {
                $user = $response->getBody()->getContents();
                $user = json_decode($user, true);
            }

            $this->validateProfileSub($credentials['id_token'], $user['sub'] ?? '');
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $user;
    }

    /**
     * Get Access Token data
     *
     * @param string $token
     * @return array
     */
    public function parseAccessToken($token)
    {
        if (! is_string($token)) {
            return [];
        }

        $token = explode('.', $token);
        $token = base64_decode($token[1]);

        return json_decode($token, true);
    }

    /**
     * Retrieve Token from Session
     *
     * @return void
     */
    public function retrieveToken()
    {
        return session()->get(self::KEYCLOAK_SESSION);
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        session()->put(self::KEYCLOAK_SESSION, $credentials);
        session()->save();
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        session()->forget(self::KEYCLOAK_SESSION);
        session()->save();
    }

    /**
     * Build a URL with params
     *
     * @param  string $url
     * @param  array $params
     * @return string
     */
    protected function buildUrl($url, $params)
    {
        return trim($url, '?') . '?' . Arr::query($params);
    }

    /**
     * Retrieve OpenId Endpoints
     *
     * @return array
     */
    protected function getOpenIdConfiguration()
    {
        $cacheKey = 'keycloak_web_guard_openid-' . $this->realm . '-' . $this->clientId;

        // From cache?
        if ($this->cacheOpenid) {
            $configuration = Cache::get($cacheKey, []);

            if (! empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if ($response->getStatusCode() === 200) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);

            throw new \Exception('[Keycloak Error] It was not possible to load OpenId configuration: ' . $e->getMessage());
        }

        // Save cache
        if ($this->cacheOpenid) {
            Cache::put($cacheKey, $configuration);
        }

        return $configuration;
    }

    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $info = $this->parseAccessToken($credentials['access_token']);
        $exp = $info['exp'] ?? 0;

        if (time() < $exp) {
            return $credentials;
        }

        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }

        $this->saveToken($credentials);
        return $credentials;
    }

    /**
     * Validate a Profile has a valid "sub"
     *
     * @link https://medium.com/@darutk/understanding-id-token-5f83f50fa02e
     * @link https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
     *
     * @param  string $idToken
     * @param  string $userSub
     * @return void
     */
    protected function validateProfileSub($idToken, $userSub)
    {
        $sub = explode('.', $idToken);
        $sub = $sub[1] ?? '';
        $sub = json_decode(base64_decode($sub), true);
        $sub = $sub['sub'] ?? '';

        if ($sub !== $userSub) {
            throw new \Exception('[Keycloak Error] User Profile is invalid');
        }
    }

    /**
     * Log a GuzzleException
     *
     * @param  GuzzleException $e
     * @return void
     */
    protected function logException(GuzzleException $e)
    {
        if (empty($e->getResponse())) {
            Log::error('[Keycloak Service] ' . $e->getMessage());
            return;
        }

        $error = [
            'request' => $e->getRequest(),
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        Log::error('[Keycloak Service] ' . print_r($error, true));
    }
}
