<?php

namespace AdvancedLearning\Oauth2Server\Services;


use AdvancedLearning\Oauth2Server\Exceptions\AuthenticationException;
use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;

class AuthenticationService implements Authenticator
{
    protected $server;

    /**
     * AuthenticationService constructor.
     *
     * @param ResourceServer|null $server Optional resource server.
     */
    public function __construct(ResourceServer $server = null)
    {
        $this->server = $server ?: $this->createServer();
    }

    /**
     * Authenticate the request. Returns modified request (probably not as SS doesn't support
     * request attributes).
     *
     * @param HTTPRequest $request The SilverStripe request object to be authenticated.
     *
     * @return HTTPRequest
     * @throws AuthenticationException
     */
    public function authenticate(HTTPRequest $request): HTTPRequest
    {
        $requestAdapter = new HttpRequestAdapter();
        $responseAdapter = new HttpResponseAdapter();

        $server = $this->getServer();
        $psrRequest = $requestAdapter->toPsr7($request);
        $psrResponse = new Response();

        try {
            $psrRequest = $server->validateAuthenticatedRequest($psrRequest);
        } catch (OAuthServerException $exception) {
            // convert to authentication exception
            throw new AuthenticationException(
                $exception->getMessage(),
                $exception->getCode(),
                $responseAdapter->fromPsr7($exception->generateHttpResponse($psrResponse))
            );
        } catch (\Exception $exception) {
            // convert to authentication exception
            throw new AuthenticationException(
                $exception->getMessage(),
                $exception->getCode(),
                $responseAdapter->fromPsr7(
                    (new OAuthServerException($exception->getMessage(), 0, 'unknown_error', 500))
                        ->generateHttpResponse($psrResponse)
                )
            );
        }
        $request = $requestAdapter->fromPsr7($psrRequest);

        // add the request attributes as custom auth headers
        foreach ($psrRequest->getAttributes() as $attribute => $value) {
            $request->addHeader($attribute, $value);
        }

        return $request;
    }

    /**
     * Override the default ResourceServer.
     *
     * @param ResourceServer $v The new ResourceServer to use.
     *
     * @return $this
     */
    public function setServer(ResourceServer $v): Authenticator
    {
        $this->server = $v;
        return $this;
    }

    /**
     * Get the ResourceServer.
     *
     * @return ResourceServer
     */
    public function getServer(): ResourceServer
    {
        return $this->server;
    }

    /**
     * Create a default ResourceServer. Used if one isn't provided.
     *
     * @return ResourceServer
     */
    protected function createServer(): ResourceServer
    {
        // Init our repositories
        $accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

        // Path to authorization server's public key
        $publicKeyPath = Environment::getEnv('OAUTH_PUBLIC_KEY_PATH');

        // Setup the authorization server
        return new ResourceServer(
            $accessTokenRepository,
            $publicKeyPath
        );
    }
}
