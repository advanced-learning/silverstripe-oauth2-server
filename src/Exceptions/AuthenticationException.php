<?php

namespace AdvancedLearning\Oauth2Server\Exceptions;


use Exception;
use SilverStripe\Control\HTTPResponse;
use Throwable;

class AuthenticationException extends Exception
{
    protected $response;

    /**
     * AuthenticationException constructor.
     *
     * @param string         $message  Exception message.
     * @param int            $code     Error code.
     * @param HTTPResponse   $response Response object for error.
     * @param Throwable|null $previous Previous exception.
     */
    public function __construct($message = "", $code = 0, HTTPResponse $response, Throwable $previous = null)
    {
        $this->response = $response;
        parent::__construct($message, $code, $previous);
    }

    /**
     * Get the error response object.
     *
     * @return HTTPResponse
     */
    public function getResponse()
    {
        return $this->response;
    }
}
