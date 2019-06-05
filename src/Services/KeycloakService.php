<?php

namespace Vizir\KeycloakWebGuard\Services;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Vizir\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;

class KeycloakService
{
    /**
     * The Cache Key for OpenId Configuration
     */
    const KEYCLOAK_OPENID_CACHE_KEY = 'keycloak_web_guard_openid';

    /**
     * Keycloak URL
     *
     * @var string
     */
    private $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    private $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    private $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    private $clientSecret;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    private $openid;

    /**
     * Singleton Constructor
     */
    public function __construct(ClientInterface $client)
    {
        $this->httpClient = $client;

        $this->baseUrl = trim(Config::get('keycloak-web.base_url'), '/');
        $this->realm = Config::get('keycloak-web.realm');
        $this->clientId = Config::get('keycloak-web.client_id');
        $this->clientSecret = Config::get('keycloak-web.client_secret');

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

        return $this->buildUrl($url, $params) . '#login';
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        return $this->buildUrl($this->openid['end_session_endpoint'], ['redirect_uri' => route('index')]);
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
            'client_secret' => $this->clientSecret,
            'grant_type' => 'authorization_code',
            'redirect_uri' => route('keycloak.callback'),
        ];

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
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return [];
        }

        $url = $this->openid['userinfo_endpoint'];
        $headers = [
            'Authorization' => 'bearer ' . $credentials['access_token'],
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
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        session()->forget(KeycloakWebGuard::KEYCLOAK_SESSION);
    }

    /**
     * Build a URL with params
     *
     * @param  string $url
     * @param  array $params
     * @return string
     */
    private function buildUrl($url, $params)
    {
        return trim($url, '?') . '?' . Arr::query($params);
    }

    /**
     * Retrieve OpenId Endpoints
     *
     * @return array
     */
    private function getOpenIdConfiguration()
    {
        $useCache = Config::get('keycloak-web.cache_openid', false);

        // From cache?
        if ($useCache) {
            $configuration = Cache::get(self::KEYCLOAK_OPENID_CACHE_KEY, []);

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
        if ($useCache) {
            Cache::put(self::KEYCLOAK_OPENID_CACHE_KEY, $configuration);
        }

        return $configuration;
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
    private function validateProfileSub($idToken, $userSub)
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
    private function logException(GuzzleException $e)
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
