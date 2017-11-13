<?php

namespace AdvancedLearning\Oauth2Server\Controllers;

use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use AdvancedLearning\Oauth2Server\Repositories\ClientRepository;
use AdvancedLearning\Oauth2Server\Repositories\ScopeRepository;
use DateInterval;
use Exception;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Environment;

class AuthoriseController extends Controller
{
    /**
     * Handles authorisation.
     *
     * @return HTTPResponse
     */
    public function index(): HTTPResponse
    {
        $psrRequest = (new HttpRequestAdapter())->toPsr7($this->getRequest());
        $psrResponse = new Response();

        $authServer = $this->getAuthorisationServer();

        try {
            return (new HttpResponseAdapter())
                ->fromPsr7($authServer->respondToAccessTokenRequest($psrRequest, $psrResponse));
        } catch (Exception $e) {
            return new HTTPResponse($e->getMessage(), 500);
        }
    }

    /**
     * Gets the OAuth2 AuthorizationServer.
     *
     * @return AuthorizationServer
     */
    protected function getAuthorisationServer(): AuthorizationServer
    {
        // Init our repositories
        $clientRepository = new ClientRepository();
        $scopeRepository = new ScopeRepository();
        $accessTokenRepository = new AccessTokenRepository();

        // Path to public and private keys
        $privateKey = Environment::getEnv('OAUTH_PRIVATE_KEY_PATH');
        // inject base bath if necessary
        $privateKey = str_replace('{BASE_DIR}', Director::baseFolder(), $privateKey);

        $encryptionKey = Environment::getEnv('OAUTH_ENCRYPTION_KEY');

        // Setup the authorization server
        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey
        );

        // Enable the client credentials grant on the server
        $server->enableGrantType(
            new ClientCredentialsGrant(),
            new DateInterval('PT1H') // access tokens will expire after 1 hour
        );

        return $server;
    }
}
