package org.example.springsecurity.auth;

import java.util.ArrayList;
import java.util.Collection;
import org.example.springsecurity.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * 1. /login 요청 시, 시큐리티가 낚아채서 대신 로그인 진행
 * 2. 로그인 완료 후, security session 생성 -> 세션 키 값 : Security ContextHolder
 * 3. security session 생성에 필요한 객체는 Authentication 타입
 * 4. Authentication 안에 User 정보가 UserDetails 타입 형태로 존재
 */

public class PrincipalDetails implements UserDetails {

  private User user;

  public PrincipalDetails(User user) {
    this.user = user;
  }

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
}
