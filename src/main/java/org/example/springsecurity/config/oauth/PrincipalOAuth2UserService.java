package org.example.springsecurity.config.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/**
 * OAuth2 구글 로그인 완료된 이후 후처리 필요
 * 1. 코드 받기(인증)
 * 2. 엑세스 토큰 받기(사용자 정보 권한 얻기)
 * 3. 사용자 프로필 정보 가져옴
 * 4-1. 회원 가입 자동 진행
 * 4-2. 회원 추가 정보 입력
 */

@Service
public class PrincipalOAuth2UserService extends DefaultOAuth2UserService {

  /**
   * 구글에서 받은 userRequest 후처리
   */
  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());
    System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken().getTokenValue());

    // 사용자 프로필 정보를 가져옴
    OAuth2User oAuth2User = super.loadUser(userRequest);

    return oAuth2User;
  }
}
