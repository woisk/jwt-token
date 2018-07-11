<?php
/*
 * +----------------------------------------------------------------------+
 * |                   At all timesI love the moment                      |
 * +----------------------------------------------------------------------+
 * | Copyright (c) 2018 http://www.Woisk.com All rights reserved.         |
 * +----------------------------------------------------------------------+
 * | This source file is subject to version 2.0 of the Apache license,    |
 * | that is bundled with this package in the file LICENSE, and is        |
 * | available through the world-wide-web at the following url:           |
 * | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 * +----------------------------------------------------------------------+
 * |      Maple Grove  <bolelin@126.com>   QQ:364956690   286013629       |
 * +----------------------------------------------------------------------+
 */


use Woisk\JwtToken\JWT;

if (!function_exists('jwt_key')) {
    function jwt_key()
    {
        return 'YCnm+wTQeHKtiEHEBe2cptKdy9dZLrYOE0zNz7scEI=';
    }
}

/**
 * 获取token
 * @param $request
 * @return bool
 * Maple Grove  <bolelin@126.com> 2018/7/9 15:32
 */
if (!function_exists('access_token')) {
    function access_token($request)
    {

        if ($request->cookie('access_token')) {
            //获取cookie token
            $token = $request->cookie('access_token');

        } elseif ($request->get('access_token')) {
            //获取request token
            $token = $request->get('access_token');

        } elseif ($request->header('authorization')) {
            //获取header token
            $token = $request->header('authorization');

        } elseif ($request->server->get('HTTP_AUTHORIZATION')) {
            //获取server token
            $token = $request->server->get('HTTP_AUTHORIZATION');

        } elseif ($request->server->get('REDIRECT_HTTP_AUTHORIZATION')) {

            $token = $request->server->get('REDIRECT_HTTP_AUTHORIZATION');
        } else {
            return false;
        }

        //过滤token
        if ($token && preg_match('/' . 'bearer' . '\s*(\S+)\b/i', $token, $matches)) {
            $token = $matches[1];
        }
        return $token;
    }
}

/**
 * token 解密
 * @param $token
 * @return object
 * Maple Grove  <bolelin@126.com> 2018/7/9 15:33
 */
if (!function_exists('jwt_decode')) {
    function jwt_decode($token)
    {
        return JWT::decode($token, jwt_key());
    }
}

if (!function_exists('jwt_encode')) {
    function jwt_encode($exp_time, $nbf_time, $uuid, $token_type, $arr=array())
    {

        $time = time(); //当前时间
        //公用信息
        $poyload =array(
                'iss' => 'woisk.com',
                'iat' => $time,
                'nbf' => $time + $nbf_time,
                'exp' => $time + $exp_time,
                'uuid' => $uuid,
                'token_type' => $token_type,
                'data' => $arr
        );
        if (is_array($arr) && !$arr) {
            $poyload = collect($poyload)->forget('data')->all();
        }

        return JWT::encode($poyload, jwt_key());
    }
}

/**
 * 获取 token UID
 * @param $request
 * @return mixed
 * Maple Grove  <bolelin@126.com> 2018/7/9 15:33
 */
if (!function_exists('access_token_uid')) {
    function access_token_uid($request)
    {
        $token = access_token($request);
        $token = jwt_decode($token);
        return $token['uuid'];
    }
}
//