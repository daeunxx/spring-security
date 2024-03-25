package org.example.springsecurity.service;

import java.util.UUID;
import org.example.springsecurity.domain.OAuth2Attribute;
import org.example.springsecurity.domain.PrincipalDetails;
import org.example.springsecurity.domain.RoleType;
import org.example.springsecurity.domain.User;
import org.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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

  @Autowired
  private UserRepository userRepository;

  private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

  /**
   * 구글에서 받은 userRequest 후처리
   * - User save
   * - return @AuthenticationPrincipal
   */
  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    // OAuth2UserRequest는 액세스 토큰과 사용자 프로필 정보를 가지고 있음
//    System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken().getTokenValue());
    System.out.println("super.loadUser(userRequest) = " + super.loadUser(userRequest));
    System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());

    // 사용자 프로필 정보를 가져옴
    String provider = userRequest.getClientRegistration().getRegistrationId();
    String usernameAttribute = userRequest.getClientRegistration().getProviderDetails()
        .getUserInfoEndpoint().getUserNameAttributeName();

    OAuth2User oAuth2User = super.loadUser(userRequest);
    OAuth2Attribute oAuth2Attribute = OAuth2Attribute.of(provider, usernameAttribute,
        oAuth2User.getAttributes());

    System.out.println(oAuth2User.getAttributes().get(usernameAttribute));

    User user = userRepository.findByUsername(oAuth2Attribute.getUsername());
    String uuid = UUID.randomUUID().toString().substring(0, 6);

    if (user == null) {
      user = new User()
          .setUsername(oAuth2Attribute.getUsername())
          .setPassword(bCryptPasswordEncoder.encode(uuid))
          .setEmail(oAuth2Attribute.getEmail())
          .setRole(RoleType.ROLE_USER)
          .setProvider(oAuth2Attribute.getProvider())
          .setProviderId(oAuth2Attribute.getProviderId());

      userRepository.save(user);
    }

    return new PrincipalDetails(user, oAuth2User.getAttributes());
  }
}
