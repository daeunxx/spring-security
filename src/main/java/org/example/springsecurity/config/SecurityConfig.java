package org.example.springsecurity.config;

import org.example.springsecurity.service.OAuth2SuccessHandler;
import org.example.springsecurity.service.PrincipalOAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  // Spring security 필터 Spring 기본 체인에 등록
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

  @Autowired
  private PrincipalOAuth2UserService principalOAuth2UserService;

  @Autowired
  private OAuth2SuccessHandler oAuth2SuccessHandler;

  // 리턴되는 객체를 IoC 컨테이너에 등록
  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    // 사이트 위변조 요청 방지
    http.csrf(AbstractHttpConfigurer::disable);

    // ROLE_ 접두사 자동으로 붙여서 비교(ROLE_ 붙으면 Exception)
    http.authorizeHttpRequests(authorizeRequest ->
        authorizeRequest
            .requestMatchers("/user/**").authenticated()  // 로그인만 하면 들어갈 수 있는 url
            .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().permitAll()
    ).formLogin(login -> login
        .loginPage("/loginForm")
        .loginProcessingUrl("/login") // /login 요청 시, 시큐리티가 낚아채서 대신 로그인 진행
        .defaultSuccessUrl("/") // 인증이 필요한 페이지에는 무조건 로그인하도록
    ).oauth2Login(oauth2 -> oauth2
        .loginPage("/loginForm")
        // 로그인 후 후처리
        // 코드는 이미 받음
        // 액세스 토큰과 사용자 프로필 정보를 request로 넘겨줌
        .userInfoEndpoint(endpoint -> endpoint
            .userService(principalOAuth2UserService))
        .successHandler(oAuth2SuccessHandler));

    return http.build();
  }
}
