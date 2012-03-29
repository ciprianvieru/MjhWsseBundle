<?php
namespace MJH\WsseBundle\Security\Firewall;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use MJH\WsseBundle\Security\Authentication\Token\WsseUserToken;

class WsseListener implements ListenerInterface
{
    protected $securityContext;
    protected $authenticationManager;
    protected $entryPoint;

    public function __construct( SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, AuthenticationEntryPointInterface $entryPoint)
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->entryPoint = $entryPoint;
    }

    public function handle( GetResponseEvent $event )
    {
        $request = $event->getRequest();
        if (!$request->headers->has('x-wsse'))
        {
            return;
        }
        $wsseHeader =  trim($request->headers->get('x-wsse'));
        if (!strlen($wsseHeader))
        {
            return;
        }

        $wsseRegex = '/UsernameToken Username="([^"]+)", PasswordDigest="([^"]+)", Nonce="([^"]+)", Created="([^"]+)"/';

        if (preg_match($wsseRegex, $wsseHeader, $matches))
        {
            $token = new WsseUserToken();
            $token->setUser( $matches[ 1 ] );

            $token->digest = $matches[ 2 ];
            $token->nonce = $matches[ 3 ];
            $token->created = $matches[ 4 ];

            try
            {
                $returnValue = $this->authenticationManager->authenticate( $token );

                if ( $returnValue instanceof TokenInterface )
                {
                    return $this->securityContext->setToken($returnValue);
                }
                else if ($returnValue instanceof Response)
                {
                    return $event->setResponse($returnValue);
                }
            } catch (\Exception $e)
            {
                //echo "exception caught " . $e->getMessage();
            }
        }

        $event->setResponse($this->entryPoint->start($request, new AuthenticationException("Foo")));
    }
}
