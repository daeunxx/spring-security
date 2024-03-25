package org.example.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import org.example.springsecurity.domain.RoleType;
import org.example.springsecurity.domain.User;
import org.example.springsecurity.repository.UserRepository;
import org.example.springsecurity.service.TokenService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

@RequiredArgsConstructor
public class JwtAuthFilter extends GenericFilterBean {
  private final TokenService tokenService;
  UserRepository userRepository;

  /**
   * 토큰 존재 여부와 유효한 토큰인지 확인
   */
  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
      FilterChain filterChain) throws IOException, ServletException {

    System.out.println("servletRequest.toString() = " + servletRequest.toString());
    System.out.println("=========");
    String token = ((HttpServletRequest) servletRequest).getHeader("access");
    System.out.println(((HttpServletResponse) servletResponse).getHeader("access"));
    System.out.println("token = " + token);

    if (token != null && tokenService.verifyToken(token)) {
      String username = tokenService.getUsername(token);
      User user = userRepository.findByUsername(username);

      Authentication authentication = getAuthentication(user);
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    filterChain.doFilter(servletRequest, servletResponse);
  }

  public Authentication getAuthentication(User user) {
    return new UsernamePasswordAuthenticationToken(user, "",
        Arrays.asList(new SimpleGrantedAuthority(String.valueOf(RoleType.ROLE_USER))));
  }
}
