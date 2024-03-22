package org.example.springsecurity.controller;

import org.example.springsecurity.domain.PrincipalDetails;
import org.example.springsecurity.domain.RoleType;
import org.example.springsecurity.domain.User;
import org.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

  @Autowired
  UserRepository userRepository;

  @Autowired
  BCryptPasswordEncoder bCryptPasswordEncoder;

  // 시큐리티 세션에는 Authentication 객체만 들어갈 수 있음
  // Authentication 객체로는 UserDetails와 OAuth2User 타입만 가능

  @GetMapping("/test/login")
  public @ResponseBody String testLogin(Authentication authentication,
      @AuthenticationPrincipal PrincipalDetails userDetails) {
    System.out.println("/test/login================");

    PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
    System.out.println("principalDetails = " + principalDetails.getUser());

    System.out.println("userDetails = " + userDetails.getUser());

    return "세션 정보 확인";
  }

  @GetMapping("/test/oauth/login")
  public @ResponseBody String testOAuthLogin(Authentication authentication,
      @AuthenticationPrincipal OAuth2User oAuth) {
    System.out.println("/test/oauth/login================");

    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
    System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

    System.out.println("oAuth = " + oAuth.getAttributes());

    return "OAuth 세션 정보 확인";
  }

  @GetMapping({"", "/"})
  public String index() {
    return "index";
  }

  @GetMapping("/user")
  public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
    System.out.println("principalDetails = " + principalDetails);
    return "user";
  }

  @GetMapping("/admin")
  public @ResponseBody String admin() {
    return "admin";
  }

  @GetMapping("/manager")
  public @ResponseBody String manager() {
    return "manager";
  }

  @GetMapping("/loginForm")
  public String loginForm() {
    return "loginForm";
  }

  @GetMapping("/joinForm")
  public String joinForm() {
    return "joinForm";
  }

  @PostMapping("/join")
  public String join(User user) {

    user.setRole(RoleType.ROLE_USER);
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    userRepository.save(user);

    return "redirect:/loginForm";
  }

  // 페이지에 하나의 권한만 준다면 @Secured 사용
  @Secured("ROLE_ADMIN")
  @GetMapping("/info")
  public @ResponseBody String info() {
    return "개인정보";
  }

  // 페이지에 여러개의 권한을 준다면 @PreAuthorize 사용
  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  @GetMapping("/data")
  public @ResponseBody String data() {
    return "데이터정보";
  }

}
