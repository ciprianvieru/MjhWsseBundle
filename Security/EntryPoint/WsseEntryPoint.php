<?php

namespace MJH\WsseBundle\Security\EntryPoint;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;

class WsseEntryPoint implements AuthenticationEntryPointInterface
{
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $ret = '';
        if ($request->get('debug')) {
            $e = $authException;
            $ret = array();
            while($e) {
                $ret[] = $e->getMessage();
                $e = $e->getPrevious();
            }
            $ret = json_encode($ret);
        }
        $response = new Response($ret, 403);

        return $response;
    }
}
