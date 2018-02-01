<?php

namespace AdvancedLearning\Oauth2Server\Controllers;

use AdvancedLearning\Oauth2Server\AuthorizationServer\Generator;
use Exception;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTP;
use SilverStripe\Control\HTTPResponse;

class AuthoriseController extends Controller
{
    /**
     * @var Generator
     */
    protected $serverGenerator;

    /**
     * AuthoriseController constructor. If no Authorization Service is passed a default one is created.
     *
     * @param Generator $serverGenerator
     */
    public function __construct(Generator $serverGenerator)
    {
        $this->serverGenerator = $serverGenerator;
        parent::__construct();
    }

    /**
     * Handles authorisation.
     *
     * @return HTTPResponse
     */
    public function index(): HTTPResponse
    {
        $body = null;
        $contentType = $this->getRequest()->getHeader('Content-Type');

        if ($contentType === 'application/json') {
            $body = json_decode($this->getRequest()->getBody(), true);
        } else {
            $body = $this->getRequest()->postVars();
        }

        if (empty($body)) {
            return $this->getErrorResponse(
                'No parameters could be found in request body. Did you correctly set the Content-Type header?',
                500
            );
        }

        // request needs parsed body
        $psrRequest = (new HttpRequestAdapter())->toPsr7($this->getRequest())
            ->withParsedBody($body);
        $psrResponse = new Response();

        $authServer = $this->serverGenerator->getServer();

        try {
            return (new HttpResponseAdapter())
                ->fromPsr7($authServer->respondToAccessTokenRequest($psrRequest, $psrResponse));
        } catch (OAuthServerException $e) {
            return $this->convertResponse($e->generateHttpResponse(new Response()));
        } catch (Exception $e) {
            return $this->getErrorResponse($e->getMessage());
        }
    }

    protected function getErrorResponse($message, $responseCode = 500)
    {
        $response = (new OAuthServerException($message, 100, 'server_error', $responseCode))
            ->generateHttpResponse(new Response());

        return $this->convertResponse($response);
    }

    protected function convertResponse(ResponseInterface $response)
    {
        return (new HttpResponseAdapter())->fromPsr7($response);
    }
}
