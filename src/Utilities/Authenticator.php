<?php
/**
 * Created by PhpStorm.
 * User: Conrad
 * Date: 23/01/2018
 * Time: 9:35 AM
 */

namespace AdvancedLearning\Oauth2Server\Utilities;


use function min;
use SilverStripe\Control\HTTPRequest;

trait Authenticator
{
    /**
     * Check request has oauth headers, and optionally check for scopes.
     *
     * @param HTTPRequest $request
     * @param array       $scopes
     *
     * @return bool
     */
    public function oauthAuthenticate(HTTPRequest $request, $scopes = [])
    {
        $headers = $request->getHeaders();

        // must have a client
        if (empty($headers['oauth_client_id'])) {
            return false;
        }

        // if scopes passed, check request contains all the scopes
        if (!empty($scopes)) {
            $matchedScopes = [];

            $requestScopes = !empty($headers['oauth_scopes']) ?
                explode(',', $headers['oauth_scopes']) :
                [];

            // if request has no scopes then authentication failed
            if (empty($requestScopes)) {
                return false;
            }

            foreach ($scopes as $scope) {
                $matchedScopes[] = in_array($scope, $requestScopes);
            }

            return (bool)min($matchedScopes);
        }

        return true;
    }
}