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
 * | Author: Maple Grove <bolelin@126.com> QQ:364956690               |
 * +----------------------------------------------------------------------+
 * | Date:2018/6/8/0:29                                                 |
 * +----------------------------------------------------------------------+
 */

namespace Woisk\JwtToken\Middleware;


use Closure;
use Exception;
use Woisk\JwtToken\Exception\BeforeValidException;
use Woisk\JwtToken\Exception\ExpiredException;
use Woisk\JwtToken\Exception\SignatureInvalidException;
use Woisk\JwtToken\JWT;

/**
 * token验证 检查是否登录
 * Class AuthCheck
 * @package Woisk\Auth\Http\Middleware
 * -------------------------------------------------------
 *  Author: Maple Grove <bolelin@126.com> QQ:364956690
 *  Date:2018/7/5/10:29
 */
class AuthCheck
{
    public $token;

    protected $header = 'authorization';
    protected $prefix = 'bearer';

    public function handle($request, Closure $next)
    {
        //获取token
        if ($request->cookie('access_token')) {

            $this->token = $request->cookie('access_token');

        } elseif ($request->get('access_token')) {

            $this->token = $request->get('access_token');

        } elseif ($request->header('authorization')) {

            $this->token = $request->header('authorization');

        } elseif ($request->server->get('HTTP_AUTHORIZATION')) {

            $this->token = $request->server->get('HTTP_AUTHORIZATION');

        } elseif ($request->server->get('REDIRECT_HTTP_AUTHORIZATION')) {

            $this->token = $request->server->get('REDIRECT_HTTP_AUTHORIZATION');
        } else {
            return res(1001, '没有令牌。不能访问');
        }

        //过滤token
        if ($this->token && preg_match('/' . $this->prefix . '\s*(\S+)\b/i', $this->token, $matches)) {
            $this->token = $matches[1];
        }


        try {

            //JWT::$leeway = 5;//当前时间减去60，把时间留点余地
            JWT::decode($this->token, jwt_key(), ['HS256']); //HS256方式，这里要和签发的时候对应

            return $next($request);

        } catch (SignatureInvalidException $e) {  //签名不正确

            return res(1002, '令牌不合法');

        } catch (BeforeValidException $e) {  // 签名在某个时间点之后才能用

            return res(1003, '令牌未生效');

        } catch (ExpiredException $e) {  // token过期

            return res(1004, '令牌过期');

        } catch (Exception $e) {  //其他错误

            return res(1005, '令牌无效');
        }


    }

}