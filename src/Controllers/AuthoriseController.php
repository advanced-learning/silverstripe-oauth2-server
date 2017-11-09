<?php

namespace AdvancedLearning\Oauth2Server\Controllers;

use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use AdvancedLearning\Oauth2Server\Repositories\ClientRepository;
use AdvancedLearning\Oauth2Server\Repositories\ScopeRepository;
use DateInterval;
use Exception;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
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
        $psrRequest = $this->toPSR7Request($this->getRequest());
        $psrResponse = new Response();

        $authServer = $this->getAuthorisationServer();

        try {
            return $this->toSSResponse($authServer->respondToAccessTokenRequest($psrRequest, $psrResponse));
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
        $clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
        $scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
        $accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

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

    /**
     * Converts a SilverStripe HTTPRequest object into a PSR7 compliant request object.
     *
     * @param HTTPRequest $request The HTTPRequest to convert.
     *
     * @return ServerRequest
     */
    protected function toPSR7Request(HTTPRequest $request): ServerRequest
    {
        $psrRequest = new ServerRequest($request->httpMethod(), $request->getURL());

        // add headers
        foreach ($request->getHeaders() as $header => $value) {
            $psrRequest = $psrRequest->withHeader($header, $value);
        }

        $psrRequest = $psrRequest->withParsedBody(json_decode($request->getBody(), true));

        return $psrRequest;
    }

    /**
     * Converts a PSR7 Response object into a SilverStripe HTTPResponse object.
     *
     * @param Response $response THe PSR7 Response object to convert.
     *
     * @return HTTPResponse
     */
    protected function toSSResponse(Response $response): HTTPResponse
    {
        $ssResponse = $this->getResponse();

        // add headers
        foreach ($response->getHeaders() as $header => $value) {
            $ssResponse->addHeader($header, $value[0]);
        }

        $ssResponse->setBody((string)$response->getBody());

        return $ssResponse;
    }
}
