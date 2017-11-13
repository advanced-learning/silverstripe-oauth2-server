<?php

namespace AdvancedLearning\Oauth2Server\Middleware;

use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Application;
use SilverStripe\Core\Environment;

/**
 * Class ResourceServerMiddleware.
 *
 * Replacement for @see \League\OAuth2\Server\Middleware\ResourceServerMiddleware
 * to make it compatible with SilverStripe.
 *
 * @package AdvancedLearning\Oauth2Server\Middleware
 */
class ResourceServerMiddleware implements HTTPMiddleware
{
    /**
     * @var Application
     */
    protected $application = null;

    /**
     * @var ResourceServer
     */
    protected $server;

    /**
     * Build error control chain for an application
     *
     * @param Application    $application The SilverStripe Application.
     * @param ResourceServer $server      Optional ResourceServer to be used in replace of the default.
     */
    public function __construct(Application $application, ResourceServer $server = null)
    {
        $this->application = $application;
        $this->server = $server;
    }

    /**
     * Process the middleware.
     *
     * @param HTTPRequest $request The incoming request.
     * @param callable    $next    The next middleware.
     *
     * @return HTTPResponse
     */
    public function process(HTTPRequest $request, callable $next)
    {
        $requestAdapter = new HttpRequestAdapter();
        $responseAdapter = new HttpResponseAdapter();

        $server = $this->getServer();
        $psrRequest = $requestAdapter->toPsr7($request);
        $psrResponse = new Response();
        
        try {
            $psrRequest = $server->validateAuthenticatedRequest($psrRequest);
        } catch (OAuthServerException $exception) {
            return $responseAdapter->fromPsr7($exception->generateHttpResponse($psrResponse));
            // @codeCoverageIgnoreStart
        } catch (\Exception $exception) {
            return $responseAdapter->fromPsr7((new OAuthServerException($exception->getMessage(), 0, 'unknown_error', 500))
                ->generateHttpResponse($psrResponse));
            // @codeCoverageIgnoreEnd
        }

        // Pass the request on to the next responder in the chain
        return $next($requestAdapter->fromPsr7($psrRequest));
    }

    /**
     * Get the Oauth2 server to handle authentication.
     *
     * @return \League\OAuth2\Server\ResourceServer
     */
    protected function getServer()
    {
        if (!empty($this->server)) {
            return $this->server;
        }

        // Init our repositories
        $accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

        // Path to authorization server's public key
        $publicKeyPath = Environment::getEnv('OAUTH_PUBLIC_KEY_PATH');

        // Setup the authorization server
        $server = new \League\OAuth2\Server\ResourceServer(
            $accessTokenRepository,
            $publicKeyPath
        );

        return $this->server = $server;
    }
}
