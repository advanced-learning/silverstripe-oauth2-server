<?php

namespace AdvancedLearning\Oauth2Server\Middleware;

use AdvancedLearning\Oauth2Server\Exceptions\AuthenticationException;
use AdvancedLearning\Oauth2Server\Services\Authenticator;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Application;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Class ResourceServerMiddleware.
 *
 * Replacement for @see \League\OAuth2\Server\Middleware\ResourceServerMiddleware
 * to make it compatible with SilverStripe.
 *
 * @package AdvancedLearning\Oauth2Server\Middleware
 */
class AuthenticationMiddleware implements HTTPMiddleware
{
    /**
     * @var Application
     */
    protected $application = null;

    /**
     * @var Authenticator
     */
    protected $authenticator;

    /**
     * Build error control chain for an application
     *
     * @param Application    $application The SilverStripe Application.
     */
    public function __construct(Application $application)
    {
        $this->application = $application;
        $this->authenticator = Injector::inst()->get(Authenticator::class);
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
        try {
            $request = $this->authenticator->authenticate($request);

            // set the current user
            if ($userID = $request->getHeader('oauth_user_id')) {
                Security::setCurrentUser(Member::get()->byID($userID));
            }
        } catch (AuthenticationException $exception) {
            return $exception->getResponse();
        }

        // Pass the request on to the next responder in the chain
        return $next($request);
    }
}
