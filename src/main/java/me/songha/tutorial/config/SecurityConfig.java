package me.songha.tutorial.config;

import lombok.RequiredArgsConstructor;
import me.songha.tutorial.oauth.exception.CustomAuthenticationEntryPoint;
import me.songha.tutorial.oauth.filter.JwtSecurityConfig;
import me.songha.tutorial.oauth.handler.CustomAccessDeniedHandler;
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/h2-console/**"
                , "/favicon.ico"
                , "/error");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 토큰을 사용하는 방식이기 때문에 csrf를 disable 한다.
                .csrf().disable()

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

                // oauth 설정
                .and()
                .oauth2Login() // "/oauth2/authorization/{registrationId}"에 요청이 들어오면, 스프링 시큐리티가 provider의 authorization-uri로 요청을 전달한다.

                // 토큰이 없는 상태서 요청되는 로그인 및 회원가입은 permitAll 설정
                .and()
                .authorizeRequests()
                .antMatchers("/view/**").permitAll()

                // 그외 요청은 인증 과정이 필요
                .anyRequest().authenticated()

                // JwtFilter를 addFilter로 등록했던 JwtSecurityConfig 적용
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

        return httpSecurity.build();
    }
}