package org.example.springsecurity.service;

import com.fasterxml.jackson.core.PrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
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
  private final ObjectMapper objectMapper;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
    String username = principalDetails.getUser().getUsername();

    Token token = tokenService.generateToken(username, RoleType.ROLE_USER);
    log.info("{}", token);

    writeTokenResponse(response, token);
  }

  private void writeTokenResponse(HttpServletResponse response, Token token) throws IOException {
    response.setContentType("text/html;charset=UTF-8");

    response.addHeader("Auth", token.getAccessToken());
    response.addHeader("Refresh", token.getRefreshToken());
    response.setContentType("application/json;charset=UTF-8");

    var writer = response.getWriter();
    writer.println(objectMapper.writer((PrettyPrinter) token));
    writer.flush();
  }
}
