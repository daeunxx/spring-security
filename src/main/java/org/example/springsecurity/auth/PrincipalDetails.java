package org.example.springsecurity.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import lombok.Data;
import org.example.springsecurity.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * 1. /login 요청 시, 시큐리티가 낚아채서 대신 로그인 진행
 * 2. 로그인 완료 후, 시큐리티 세션 생성 -> 세션 키 값 : Security ContextHolder
 * 3. 시큐리티 세션 생성에 필요한 객체는 Authentication 타입
 * 4-1. Authentication 안에 User 정보가 UserDetails 타입 형태로 존재(일반 로그인)
 * 4-2. User 정보 OAuth2User 타입 형태로 존재(SNS 로그인)
 */

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

  private User user;
  Map<String, Object> attributes;

  // 일반 로그인 생성자
  public PrincipalDetails(User user) {
    this.user = user;
  }

  // OAuth 로그인 생성자
  public PrincipalDetails(User user, Map<String, Object> attributes) {
    this.user = user;
    this.attributes = attributes;
  }

  // === UserDetails 메서드 === //

  /**
   * User 권한 리턴
   */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    Collection<GrantedAuthority> collection = new ArrayList<>();
    collection.add((GrantedAuthority) () -> user.getRole().toString());
    return collection;
  }

  @Override
  public String getPassword() {
    return user.getPassword();
  }

  @Override
  public String getUsername() {
    return user.getUsername();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  /**
   * 휴면 계정 전환
   * (현재 시간 - 마지막 로그인 시간) > 1년 -> return false
   */
  @Override
  public boolean isEnabled() {
    return true;
  }

  // === OAuth2User 메서드 === //

  @Override
  public String getName() {
    return null;
  }

  @Override
  public Map<String, Object> getAttributes() {
    return attributes;
  }
}
