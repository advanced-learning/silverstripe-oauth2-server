<?php

namespace AdvancedLearning\Oauth2Server\Middleware;

use AdvancedLearning\Oauth2Server\Exceptions\AuthenticationException;
use AdvancedLearning\Oauth2Server\Services\Authenticator;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Application;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\Connect\DatabaseException;
use SilverStripe\ORM\DB;
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
    public function __construct()
    {
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
        // don't authenticate if being run from command line
        if (Director::is_cli()) {
            return $next($request);
        }

        try {
            $request = $this->authenticator->authenticate($request);

            // set the current user
            if ($userID = $request->getHeader('oauth_user_id')) {
                Security::setCurrentUser(Member::get()->byID($userID));
            }
        } catch (AuthenticationException $exception) {
            // for middleware do nothing
        } catch (DatabaseException $exception) {
            // db not ready, ignore
        }

        // Pass the request on to the next responder in the chain
        return $next($request);
    }
}
