<?php

namespace AdvancedLearning\Oauth2Server\Tests;

use AdvancedLearning\Oauth2Server\Models\Client;
use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use AdvancedLearning\Oauth2Server\Repositories\ClientRepository;
use AdvancedLearning\Oauth2Server\Repositories\ScopeRepository;
use function file_get_contents;
use function file_put_contents;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use SilverStripe\Dev\SapphireTest;
use function sys_get_temp_dir;

class OAuthServerTest extends SapphireTest
{
    protected static $fixture_file = 'OAuthFixture.yml';

    protected static $keyFile = 'private.key';

    /**
     * Setup test environment.
     */
    public function setUp()
    {
        // copy private key so we can set correct permissions, file gets removed when tests finish
        $path = $this->getPrivateKeyPath();
        file_put_contents($path, file_get_contents(__DIR__ . '/' . self::$keyFile));
        chmod($path, 0660);

        return parent::setUp();
    }

    /**
     * Test a client grant.
     */
    public function testClientGrant()
    {
        $server = $this->getAuthorisationServer();
        // Enable the client credentials grant on the server
        $server->enableGrantType(
            new ClientCredentialsGrant(),
            new \DateInterval('PT1H') // access tokens will expire after 1 hour
        );

        $client = $this->objFromFixture(Client::class, 'webapp');

        $request = (new ServerRequest(
            'POST',
            '',
            ['Content-Type' => 'application/json']
        ))->withParsedBody([
            'grant_type' => 'client_credentials',
            'client_id' => $client->ID,
            'client_secret' => $client->Secret,
            'scope' => 'members'
        ]);

        $response = new Response();
        $response = $server->respondToAccessTokenRequest($request, $response);

        $data = json_decode((string)$response->getBody(), true);

        $this->assertArrayHasKey('token_type', $data, 'Response should have a token_type');
        $this->assertArrayHasKey('expires_in', $data, 'Response should have expire time for token');
        $this->assertArrayHasKey('access_token', $data, 'Response should have a token');
        $this->assertEquals('Bearer', $data['token_type'], 'Token type should be Bearer');
    }

    /**
     * Setup the Authorization Server.
     *
     * @return AuthorizationServer
     */
    protected function getAuthorisationServer()
    {
        // Init our repositories
        $clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
        $scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
        $accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

        // Path to public and private keys
        $privateKey = $this->getPrivateKeyPath();
        $encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen';

        // Setup the authorization server
        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey
        );

        return $server;
    }

    /**
     * Get the full path the private key.
     *
     * @return string
     */
    protected function getPrivateKeyPath()
    {
        return sys_get_temp_dir() . '/' . self::$keyFile;
    }

    /**
     * Cleanup test environment.
     */
    protected function tearDown()
    {
        parent::tearDown();
        // remove private key after tests have finished
        unlink($this->getPrivateKeyPath());
    }
}
