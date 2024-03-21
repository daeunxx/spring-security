package org.example.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  // Spring security 필터 Spring 기본 체인에 등록
public class SecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    // 사이트 위변조 요청 방지
    http.csrf(AbstractHttpConfigurer::disable);

    // ROLE_ 접두사 자동으로 붙여서 비교(ROLE_ 붙으면 Exception)
    http.authorizeRequests(authorizeRequest ->
        authorizeRequest
            .requestMatchers("/user/**").authenticated()
            .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().permitAll()
    ).formLogin(login ->
        login
            .loginPage("/login")
            .defaultSuccessUrl("/") // 인증이 필요한 페이지에는 무조건 로그인하도록
    );

    return http.build();
  }
}
