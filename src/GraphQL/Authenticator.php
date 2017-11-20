<?php

namespace AdvancedLearning\Oauth2Server\GraphQL;


use AdvancedLearning\Oauth2Server\Exceptions\AuthenticationException;
use AdvancedLearning\Oauth2Server\Models\Client;
use function is_null;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\Auth\AuthenticatorInterface;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;
use function substr;

class Authenticator implements AuthenticatorInterface
{
    public function authenticate(HTTPRequest $request)
    {
        $authenticator = Injector::inst()->get(\AdvancedLearning\Oauth2Server\Services\Authenticator::class);

        try {
            $request = $authenticator->authenticate($request);


            if ($userId = $request->getHeader('oauth_user_id')) {
                return Member::get()->filter(['Email' => $userId])->first();

                // return a fake member for the client
            } else if ($clientId = $request->getHeader('oauth_client_id')) {
                $member = new Member();
                $client = Client::get()->byID($clientId);

                $member->FirstName = $client->Name;

                return $member;
            }

            throw new ValidationException('Could not find a valid client/user');
        } catch (AuthenticationException $exception) {
            throw new ValidationException($exception->getMessage());
        }
    }

    public function isApplicable(HTTPRequest $request)
    {
        return !is_null($this->getToken($request));
    }

    /**
     * Extract the token from the authorization header.
     *
     * @param HTTPRequest $request The request container the token.
     *
     * @return null|string
     */
    protected function getToken(HTTPRequest $request): ?string
    {
        if ($authHeader = $request->getHeader('Authorization')) {
            if (stripos($authHeader, 'Bearer ') === 0) {
                return substr($authHeader, 6);
            }
        }

        return null;
    }
}
