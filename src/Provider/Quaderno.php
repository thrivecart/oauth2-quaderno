<?php
namespace marcfowler\OAuth2\Client\Provider;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Quaderno extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var string
     */
    public $baseUri = 'https://quadernoapp.com';

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->baseUri . '/oauth/authorize';
    }

    /**
     * Get access token url to retrieve token
     *
     * @param array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->baseUri . '/oauth/token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->baseUri . '/api/authorization';
    }

    /**
     * Get deauthorization url to end OAuth flow
     *
     * @return string
     */
    public function getBaseDeauthorizationUrl()
    {
        return $this->baseUri . '/oauth/deauthorize';
    }

    /**
     * Get the default scopes used by this provider.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return ['read_only'];
    }

    /**
     * Check a provider response for errors.
     *
     * @param ResponseInterface $response
     * @param array|string $data
     *
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            if(isset($data['errors'])) {
                $error_string = array();
                foreach($data['errors'] as $k => $v) {
                    if(is_array($v)) {
                        $error_string[] = "{$k}: " . implode(', ', $v);
                    } else {
                        $error_string[] = "{$k}: {$v}";
                    }
                }
                $error_string = implode('. ', $error_string);

                throw new IdentityProviderException(
                    $error_string ?: $response->getReasonPhrase(),
                    $response->getStatusCode(),
                    $response
                );
                return;
            }

            throw new IdentityProviderException(
                $data['error'] ?: $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param array $response
     * @param AccessToken $token
     *
     * @return QuadernoResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new QuadernoResourceOwner($response);
    }

    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        $accessToken = parent::createAccessToken($response, $grant);

        // create the parent access token and add properties from response
        foreach ($response as $k => $v) {
            if (!property_exists($accessToken, $k)) {
                $accessToken->$k = $v;
            }
        }

        return $accessToken;
    }

    /**
     * @param string $accessToken Access token to revoke
     *
     * @return mixed
     */
    public function deauthorize($accessToken)
    {
        $request = $this->createRequest(
            self::METHOD_POST,
            $this->getBaseDeauthorizationUrl(),
            null,
            [
                'body' => $this->buildQueryString([
                    'token' => $accessToken,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]),
            ]
        );

        return $this->getParsedResponse($request);
    }
}