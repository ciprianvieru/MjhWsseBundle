<?php
namespace MJH\WsseBundle\Security\Authentication\Request;

use \Exception;
use \DateTime;

class WsseRequest
{
    protected $username;
    protected $secret;

    protected $digest;
    protected $nonce;
    protected $timestamp;

    protected $url;
    protected $post_data = NULL;

    protected $result = NULL;
    protected $error = NULL;
    protected $errorcode = NULL;

    public function __construct( $url, $post_data = NULL, $username = NULL, $secret = NULL )
    {
        $this->setSecret( $secret );
        $this->setUsername( $username );
        $this->setUrl( $url );
        $this->setPostData( $post_data );
    }

    public function setUsername( $username )
    {
        $this->username = $username;
    }

    public function setSecret( $secret )
    {
        $this->secret = $secret;
    }

    public function setUrl( $url )
    {
        $this->url = $url;
    }

    public function setPostData( $post_data )
    {
        $this->post_data = $post_data;
    }

    protected function setDigest()
    {
        $this->setTimestamp();
        $this->setNonce();

        if ( !$this->nonce || !$this->timestamp || !$this->secret )
        {
            throw new \Exception('Insufficient information to generate digest');
        }

        $this->digest = base64_encode( sha1( $this->nonce . $this->timestamp . $this->secret, true ) );
    }

    public function getDigest()
    {
        return $this->digest;
    }

    protected function setTimestamp()
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $this->timestamp = (string)$now->format( 'Y-m-d\TH:i:s\Z' );
    }

    protected function getTimestamp()
    {
        return $this->timestamp;
    }

    protected function setNonce()
    {
        $this->nonce = substr( base64_encode( sha1( time() . 'salt' ) ), 0, 16 );
    }

    protected function getNonce()
    {
        return $this->nonce;
    }

    protected function getWsseHeader()
    {
        return sprintf( 'X-WSSE: UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"',
            $this->username,
            $this->digest,
            $this->nonce,
            $this->timestamp
        );
    }

    protected function setResult( $result )
    {
        $this->result = $result;
    }

    public function getResult()
    {
        return $this->result;
    }

    protected function setError( $error )
    {
        $this->error = $error;
    }

    public function getError()
    {
        return $this->error;
    }

    protected function setErrorCode( $errorcode )
    {
        $this->errorcode = $errorcode;
    }

    public function getErrorCode()
    {
        return $this->errorcode;
    }

    public function hasError()
    {
        return ($this->error || $this->errorcode);
    }

    public function sendRequest()
    {
        $this->setDigest();

        if ( !$this->username )
        {
            throw new \Exception('No user provided');
        }

        return $this->sendCurlRequest();
    }

    protected function sendCurlRequest()
    {
        $headers = array(
//            'Content-Type: application/json; charset=utf-8',
            $this->getWsseHeader()
        );

        $post = http_build_query( $this->post_data );

        $ch = curl_init( $this->url );

        curl_setopt( $ch, CURLOPT_HTTPHEADER, $headers );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
        //        if ($this->post_data)
        {
            curl_setopt( $ch, CURLOPT_POST, true );
            curl_setopt( $ch, CURLOPT_POSTFIELDS, $this->post_data );
        }

        $result = curl_exec( $ch );

        if ( $result === false )
        {
            $this->setError( curl_error( $ch ) );
            $this->setErrorCode( curl_errno( $ch ) );
            $this->setResult( NULL );
        }
        else
        {
            $this->setResult( $result );
            $this->setError( NULL );
            $this->setErrorCode( NULL );
        }

        curl_close( $ch );

        // return true if we get all the way through -- check hasError() for errors.
        return true;

    }

    /**
     * @return mixed
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return mixed
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * @return mixed
     */
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * @return null
     */
    public function getPostData()
    {
        return $this->post_data;
    }

    
}