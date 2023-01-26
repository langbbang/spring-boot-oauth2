package me.songha.tutorial.api.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// 참고 : https://deeplify.dev/back-end/spring/oauth2-social-login
// https://lotuus.tistory.com/104
// https://velog.io/@appti/Spring-Security-OAuth2-%EC%B9%B4%EC%B9%B4%EC%98%A4#spring-security-oauth2----%EC%B9%B4%EC%B9%B4%EC%98%A4
// https://sudo-minz.tistory.com/78

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    /**
     * 1. 클라이언트 서버를 리소스 서버에 등록한다. 그렇게 클라이언트가 얻는 정보는 client_id, client_secret
     * 리소스 서버가 가지는 정보는 client_id, client_secret, redirect_url, scope
     *
     * 2. 리소스 오너는 리소스 서버에 직접 로그인을 요청한다. 요청할 때 보내는 정보는
     * e.g. http://리소스서버/oauth ? client_id=1 & scope=b,c & redirect_url=http://클라이언트서버/callback
     *
     * 3. 로그인을 성공하면 전달 받은 client_id와 redirect_url 가 리소스 서버가 가진 값과 동일한지 확인 후
     * 최조 1회에 한하여 리소스 서버는 scope 정보 제공 동의를 리소스 오너에게 확인 받음
     * 그리고 리소스 서버는 user_id=1 이 scope=b,c 에 동의하였다는 정보를 기록한다.
     *
     * 4. 리소스 서버는 authorization_code 을 담아 헤더의 Location 값에 redirect 주소를 담아 리소스 오너에게 전송한다.
     * 헤더의 Location 값에 의해 자동적으로 클라이언트 서버로 리다이렉트 되며 클라이언트는 authorization_code 을 가지게 된다.
     *
     * 5. 클라이언트 서버는 리소스 서버에 grant_type, client_id, client_secret, authorization_code, redirect_url 값을 담아 전송한다.
     *
     * 6. 리소스 서버는 authorization_code 를 통해서 client_id, client_secret 의 값이 서버가 갖고 있는 값과 동일한지 확인 후
     * access_token 을 발급한다.
     */


    /**
     * 1. Security 설정의
     * .oauth2Login()authorizationEndpoint().baseUri("/oauth2/authorization") 을 통해서
     * "/oauth2/authorization/{registrationId}"에 요청이 들어오면,
     * 스프링 시큐리티가 provider의 authorization-uri로 요청을 전달한다.
     * 카카오의 경우 https://kauth.kakao.com/oauth/authorize 로 redirect 된다.
     *
     * 2. 일련의 로그인 과정을 거친 후
     * CustomOAuth2UserService.loadUser(...) 를 통해 oauth2 인증 성공 시
     * 회원가입이 안되어있다면 계정 정보 DB INSERT 작업을 거치고,
     * 있다면 변경사항을 영속성 컨텍스트 개념을 활용하여 DB UPDATE 를 진행한다.
     *
     * 3. 로그인 인증에 성공 시
     * OAuth2AuthenticationSuccessHandler.onAuthenticationSuccess(...) 에 정의한 순서대로
     * AccessToken 과 RefreshToken 을 발급한다.
     */
}
