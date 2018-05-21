<?php
/**
 * Created by PhpStorm.
 * User: conrad
 * Date: 21/05/18
 * Time: 3:59 PM
 */

namespace AdvancedLearning\Oauth2Server\Tests;


use AdvancedLearning\Oauth2Server\Utilities\Authenticator;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Dev\SapphireTest;

class UtilitiesAuthenticatorTest extends SapphireTest
{
    use Authenticator;

    public function testAuthentication()
    {
        $request = new HTTPRequest('GET', '/test');
        $request->addHeader('oauth_client_id', 'someclientid');
        $request->addHeader('oauth_scopes', 'scope1,scope2');

        $authenticated = $this->oauthAuthenticate($request, ['scope1', 'scope2']);

        $this->assertTrue($authenticated, 'Request should have been authenticated');
    }

    public function testFailedScopeAuthentication()
    {
        $request = new HTTPRequest('GET', '/test');
        $request->addHeader('oauth_client_id', 'someclientid');
        $request->addHeader('oauth_scopes', 'scope1');

        $authenticated = $this->oauthAuthenticate($request, ['scope1', 'scope2']);

        $this->assertFalse($authenticated, 'Request should have failed due to invalid scopes');
    }

}
