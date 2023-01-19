package me.songha.tutorial.config;

import lombok.RequiredArgsConstructor;
import me.songha.tutorial.api.repository.UserRefreshTokenRepository;
import me.songha.tutorial.oauth.domain.RoleType;
import me.songha.tutorial.oauth.exception.CustomAuthenticationEntryPoint;
import me.songha.tutorial.oauth.filter.JwtSecurityConfig;
import me.songha.tutorial.oauth.handler.CustomAccessDeniedHandler;
import me.songha.tutorial.oauth.handler.OAuth2AuthenticationFailureHandler;
import me.songha.tutorial.oauth.handler.OAuth2AuthenticationSuccessHandler;
import me.songha.tutorial.oauth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import me.songha.tutorial.oauth.service.CustomOAuth2UserService;
import me.songha.tutorial.oauth.token.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

/**
 * @Description ::
 */
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorized 어노테이션을 메소드 단위로 사용하기 위해 추가함
public class SecurityConfig {
    // constructor 주입 방식을 통해 주입
    private final TokenProvider tokenProvider;
    private final CorsFilter corsFilter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomOAuth2UserService oAuth2UserService;
    private final AppProperties appProperties;
    private final UserRefreshTokenRepository userRefreshTokenRepository;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/h2-console/**"
                , "/favicon.ico"
                , "/error");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 교차 출처 리소스 공유(Cross-Origin Resource Sharing, CORS)는 추가 HTTP 헤더를 사용하여,
                // 한 출처에서 실행 중인 웹 애플리케이션이
                // 다른 출처의 선택한 자원에 접근할 수 있는 권한을 부여하도록 브라우저에 알려주는 체제입니다.
                // 웹 애플리케이션은 리소스가 자신의 출처(도메인, 프로토콜, 포트)와 다를 때 교차 출처 HTTP 요청을 실행합니다.
                .cors()

                // 토큰을 사용하는 방식이기 때문에 csrf를 disable 한다.
                .and()
                .csrf().disable() // 활성화되어 있다면 get 요청 시 csrf 파라미터를 매번 검사하기 때문에 비활성화
                .formLogin().disable() // form 화면으로의 로그인 기능 비활성, rest api 이기 때문
                .httpBasic().disable() // 기본설정 비활성, 기본설정은 비인증시 로그인폼 화면으로 리다이렉트 된다.

                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

                // Exception을 핸들링할 때 만들었던 클래스들을 추가한다.
                .exceptionHandling()
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler)

                // h2-console 를 위한 설정 적용
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                // 특정 uri 패턴은 특정 권한 소유자만 접근 가능
                .antMatchers("/api/**").hasAnyAuthority(RoleType.USER.getCode())
                .antMatchers("/api/**/admin/**").hasAnyAuthority(RoleType.ADMIN.getCode())
                // 토큰이 없는 상태서 요청되는 로그인 및 회원가입은 permitAll 설정
                .antMatchers("/view/**", "/").permitAll()

                // 그외 요청은 인증 과정이 필요
                .anyRequest().authenticated()

                // oauth 설정
                .and()
                // "/oauth2/authorization/{registrationId}"에 요청이 들어오면, 스프링 시큐리티가 provider의 authorization-uri로 요청을 전달한다.
                .oauth2Login()

                .authorizationEndpoint()
                .baseUri("/oauth2/authorization") // 해당 url로 접근 시 oauth 로그인을 요청한다
                .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository())

                // 코드 통일을 위해서 config 에도 redirect 주소를 작성한다.
                .and()
                .redirectionEndpoint()
                .baseUri("/login/oauth2/code/*")

                // oAuth2UserService 서비스는 oauth로 유저정보를 받아오게되면 그 유저정보를 oauth2 인증 유저 객체로 등록하게끔 구현된 커스텀 클래스
                .and()
                .userInfoEndpoint()
                .userService(oAuth2UserService)

                // 엑세스 토큰과 리프레시 토큰을 유저정보를 바탕으로 생성하여 프론트에 전달
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler()) // 정상적으로 유저가 잘 인증되어 등록되면 실행되는 클래스
                .failureHandler(oAuth2AuthenticationFailureHandler());// 인증에 실패하였을 경우 실행되는 클래스

        // JwtFilter를 addFilter로 등록했던 JwtSecurityConfig 적용
        httpSecurity.apply(new JwtSecurityConfig(tokenProvider));

        return httpSecurity.build();
    }

    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(
                tokenProvider,
                appProperties,
                userRefreshTokenRepository,
                oAuth2AuthorizationRequestBasedOnCookieRepository()
        );
    }

    @Bean
    public OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
        return new OAuth2AuthenticationFailureHandler(oAuth2AuthorizationRequestBasedOnCookieRepository());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}