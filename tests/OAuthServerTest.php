<?php

namespace AdvancedLearning\Tests\Oauth2Server;

use AdvancedLearning\Oauth2Server\AuthorizationServer\DefaultGenerator;
use AdvancedLearning\Oauth2Server\Controllers\AuthoriseController;
use AdvancedLearning\Oauth2Server\Entities\UserEntity;
use AdvancedLearning\Oauth2Server\Middleware\AuthenticationMiddleware;
use AdvancedLearning\Oauth2Server\Models\Client;
use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use AdvancedLearning\Oauth2Server\Repositories\ClientRepository;
use AdvancedLearning\Oauth2Server\Repositories\RefreshTokenRepository;
use AdvancedLearning\Oauth2Server\Repositories\ScopeRepository;
use AdvancedLearning\Oauth2Server\Repositories\UserRepository;
use AdvancedLearning\Oauth2Server\Services\AuthenticationService;
use AdvancedLearning\Oauth2Server\Services\Authenticator;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Lcobucci\JWT\Parser;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Grant\PasswordGrant;
use Robbie\Psr7\HttpRequestAdapter;
use SilverStripe\Control\HTTPApplication;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Kernel;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Dev\TestKernel;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

use function file_get_contents;
use function file_put_contents;
use function sys_get_temp_dir;

class OAuthServerTest extends SapphireTest
{
    use CryptTrait;

    protected static $fixture_file = 'tests/OAuthFixture.yml';

    protected static $privateKeyFile = 'private.key';

    protected static $publicKeyFile = 'public.key';

    /**
     * Setup test environment.
     */
    public function setUp()
    {
        parent::setUp();

        // copy private key so we can set correct permissions, file gets removed when tests finish
        $path = $this->getPrivateKeyPath();
        file_put_contents($path, file_get_contents(__DIR__ . '/' . self::$privateKeyFile));
        chmod($path, 0660);
        Environment::setEnv('OAUTH_PRIVATE_KEY_PATH', $path);

        // copy public key
        $path = $this->getPublicKeyPath();
        file_put_contents($path, file_get_contents(__DIR__ . '/' . self::$publicKeyFile));
        chmod($path, 0660);
        Environment::setEnv('OAUTH_PUBLIC_KEY_PATH', $path);

        Security::force_database_is_ready(true);

        $this->setEncryptionKey('lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen');
    }

    /**
     * Test a client grant.
     */
    public function testClientGrant()
    {
        $response = $this->generateClientAccessToken();
        $data = json_decode((string)$response->getBody(), true);

        $this->assertArrayHasKey('token_type', $data, 'Response should have a token_type');
        $this->assertArrayHasKey('expires_in', $data, 'Response should have expire time for token');
        $this->assertArrayHasKey('access_token', $data, 'Response should have a token');
        $this->assertEquals('Bearer', $data['token_type'], 'Token type should be Bearer');
    }

    public function testPasswordGrant()
    {
        $userRepository = new UserRepository();
        $refreshRepository = new RefreshTokenRepository();

        $server = $this->getAuthorisationServer();
        $server->enableGrantType(
            new PasswordGrant($userRepository, $refreshRepository),
            new \DateInterval('PT1H')
        );

        $client = $this->objFromFixture(Client::class, 'webapp');
        $member = $this->objFromFixture(Member::class, 'member1');

        $request = (new ServerRequest(
            'POST',
            '',
            ['Content-Type' => 'application/json']
        ))->withParsedBody([
            'grant_type' => 'password',
            'client_id' => $client->Identifier,
            'client_secret' => $client->Secret,
            'scope' => 'members',
            'username' => $member->Email,
            'password' => 'password1'
        ]);

        $response = new Response();
        $response = $server->respondToAccessTokenRequest($request, $response);

        $data = json_decode((string)$response->getBody(), true);

        // decode refresh token
        $refreshToken = json_decode($this->decrypt($data['refresh_token']), true);
        $tokenRepo = new RefreshTokenRepository();

        $this->assertNotEmpty($data, 'Should have received response data');
        $this->assertArrayHasKey('token_type', $data, 'Response should have a token_type');
        $this->assertArrayHasKey('expires_in', $data, 'Response should have expire time for token');
        $this->assertArrayHasKey('access_token', $data, 'Response should have a token');
        $this->assertEquals('Bearer', $data['token_type'], 'Token type should be Bearer');
        $this->assertNotNull($tokenRepo->findToken($refreshToken['refresh_token_id']), 'Response should have a refresh token');

        $tokenRepo->revokeRefreshToken($refreshToken['refresh_token_id']);
        $this->assertTrue($tokenRepo->isRefreshTokenRevoked($refreshToken['refresh_token_id']), 'Token should be revoked');
    }

    public function testMiddleware()
    {
        $response = $this->generateClientAccessToken();
        $data = json_decode((string)$response->getBody(), true);
        $token = $data['access_token'];

        $server = $this->getResourceServer();

        // set the resource server on authenticator service
        Injector::inst()->get(Authenticator::class)->setServer($server);

        $request = new HTTPRequest('GET', '/');
        $request->addHeader('authorization', 'Bearer ' . $token);
        // fake server port
        $_SERVER['SERVER_PORT'] = 443;

        // Mock app
        $app = new HTTPApplication(new TestKernel(BASE_PATH));
        $app->getKernel()->setEnvironment(Kernel::LIVE);

        $result = (new AuthenticationMiddleware($app))->process($request, function () {
            return null;
        });

        $this->assertNull($result, 'Resource Server shouldn\'t modify the response');
    }

    public function testAuthoriseController()
    {
        $controller = new AuthoriseController(new DefaultGenerator());

        $client = $this->objFromFixture(Client::class, 'webapp');
        $request = $this->getClientRequest($client);

        /**
         * @var HTTPResponse $response
         */
        $response = $controller->setRequest(
            (new HttpRequestAdapter())
                ->fromPsr7($request)
                // controller expects a string
                ->setBody(json_encode($request->getParsedBody()))
        )
            ->index();

        $this->assertInstanceOf(HTTPResponse::class, $response, 'Should receive a response object');
        $this->assertEquals(200, $response->getStatusCode(), 'Should receive a 200 response code');

        // check for access token
        $data = json_decode($response->getBody(), true);
        $this->assertArrayHasKey('token_type', $data, 'Response should have a token_type');
        $this->assertArrayHasKey('expires_in', $data, 'Response should have expire time for token');
        $this->assertArrayHasKey('access_token', $data, 'Response should have a token');
        $this->assertEquals('Bearer', $data['token_type'], 'Token type should be Bearer');
    }

    public function testUserEntity()
    {
        $member = $this->objFromFixture(Member::class, 'member1');
        $entity = new UserEntity($member);

        $this->assertEquals($member->ID, $entity->getMember()->ID, 'User entity member should have been set');
    }

    public function testGraphQLClient()
    {
        // generate token
        $response = $this->generateClientAccessToken();
        $data = json_decode((string)$response->getBody(), true);
        $token = $data['access_token'];

        // create request
        $request = new HTTPRequest('GET', '/');
        $request->addHeader('authorization', 'Bearer ' . $token);
        // fake server port
        $_SERVER['SERVER_PORT'] = 443;

        $member = (new \AdvancedLearning\Oauth2Server\GraphQL\Authenticator())->authenticate($request);

        $this->assertEquals('My Web App', $member->FirstName, 'Member FirstName should be same as client name');
        $this->assertEquals(0, $member->ID, 'Member should not have and ID');
    }

    public function testGraphQLMember()
    {
        $userRepository = new UserRepository();
        $refreshRepository = new RefreshTokenRepository();

        $server = $this->getAuthorisationServer();
        $server->enableGrantType(
            new PasswordGrant($userRepository, $refreshRepository),
            new \DateInterval('PT1H')
        );

        $client = $this->objFromFixture(Client::class, 'webapp');
        $member = $this->objFromFixture(Member::class, 'member1');

        $request = (new ServerRequest(
            'POST',
            '',
            ['Content-Type' => 'application/json']
        ))->withParsedBody([
            'grant_type' => 'password',
            'client_id' => $client->Identifier,
            'client_secret' => $client->Secret,
            'scope' => 'members',
            'username' => $member->Email,
            'password' => 'password1'
        ]);

        $response = new Response();
        $response = $server->respondToAccessTokenRequest($request, $response);

        $data = json_decode((string)$response->getBody(), true);
        $token = $data['access_token'];

        // check for fn/ln
        $decoded = (new Parser())->parse($token);

        $this->assertEquals('My', $decoded->getClaim('fn'), 'First name should be correctly set');
        $this->assertEquals('Test', $decoded->getClaim('ln'), 'Last name should be correctly set');

        // create request
        $request = new HTTPRequest('GET', '/');
        $request->addHeader('authorization', 'Bearer ' . $token);
        // fake server port
        $_SERVER['SERVER_PORT'] = 443;

        $authMember = (new \AdvancedLearning\Oauth2Server\GraphQL\Authenticator())->authenticate($request);

        $this->assertEquals($member->ID, $authMember->ID, 'Member should exist in DB');
    }

    /**
     * @expectedException \AdvancedLearning\Oauth2Server\Exceptions\AuthenticationException
     */
    public function testAuthenticationException()
    {
        $service = new AuthenticationService();
        $request = new HTTPRequest('GET', '/test');

        $service->authenticate($request);
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
        $encryptionKey = $this->encryptionKey;

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
     * Get the resource server.
     *
     * @return \League\OAuth2\Server\ResourceServer
     */
    protected function getResourceServer()
    {
        // Init our repositories
        $accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

        // Path to authorization server's public key
        $publicKeyPath = $this->getPublicKeyPath();

        // Setup the authorization server
        $server = new \League\OAuth2\Server\ResourceServer(
            $accessTokenRepository,
            $publicKeyPath
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
        return sys_get_temp_dir() . '/' . self::$privateKeyFile;
    }

    /**
     * Get the full path the public key.
     *
     * @return string
     */
    protected function getPublicKeyPath()
    {
        return sys_get_temp_dir() . '/' . self::$publicKeyFile;
    }

    /**
     * Cleanup test environment.
     */
    protected function tearDown()
    {
        parent::tearDown();
        // remove private key after tests have finished
        unlink($this->getPrivateKeyPath());
        // remove public key after tests have finished
        unlink($this->getPublicKeyPath());
    }

    /**
     * Generates a response with an access token using the client grant.
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    protected function generateClientAccessToken()
    {
        $server = $this->getAuthorisationServer();
        // Enable the client credentials grant on the server
        $server->enableGrantType(
            new ClientCredentialsGrant(),
            new \DateInterval('PT1H') // access tokens will expire after 1 hour
        );

        $client = $this->objFromFixture(Client::class, 'webapp');

        $request = $this->getClientRequest($client);

        $response = new Response();
        return $server->respondToAccessTokenRequest($request, $response);
    }

    /**
     * Get PSR7 request object to be used for a client grant.
     *
     * @param Client $client
     *
     * @return ServerRequest
     */
    protected function getClientRequest(Client $client)
    {
        // setup server vars
        $_SERVER['SERVER_PORT'] = 80;
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';

        return (new ServerRequest(
            'POST',
            '',
            ['Content-Type' => 'application/json']
        ))->withParsedBody([
            'grant_type' => 'client_credentials',
            'client_id' => $client->Identifier,
            'client_secret' => $client->Secret,
            'scope' => 'members'
        ]);
    }

}
