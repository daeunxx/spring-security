package org.example.springsecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.springsecurity.domain.PrincipalDetails;
import org.example.springsecurity.domain.RoleType;
import org.example.springsecurity.domain.Token;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

  @Autowired
  private final TokenService tokenService;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException {

    PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
    String username = principalDetails.getUser().getUsername();

    Token token = tokenService.generateToken(username, RoleType.ROLE_USER);
    log.info("{}", token);

    // 토큰 설정
    response.setContentType("text/html");
    response.setCharacterEncoding("UTF-8");
    response.addHeader("access", token.getAccessToken());
    response.addHeader("refresh", token.getRefreshToken());

    System.out.println(response.getHeader("access"));
    System.out.println(response.getHeader("refresh"));

    // json 형태로 반환
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    response.getWriter().println(new ObjectMapper().writeValueAsString(token));
    response.getWriter().flush();
  }
}
