package org.example.springsecurity.auth;

import org.example.springsecurity.domain.User;
import org.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 1. loginProcessingUrl("/login") 요청
 * 2. UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 메서드 실행
 */
@Service
public class PrincipalDetailsService implements UserDetailsService {

  @Autowired
  private UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    User findUser = userRepository.findByUsername(username);

    if (findUser != null) {
      return new PrincipalDetails(findUser);
    }
    return null;
  }
}
