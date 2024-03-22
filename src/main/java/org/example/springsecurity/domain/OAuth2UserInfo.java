package org.example.springsecurity.domain;

import java.util.Map;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class OAuth2UserInfo {

  private Map<String, Object> attributes;
  private String providerId;
  private String provider;
  private String email;
  private String name;

  public OAuth2UserInfo(String provider, Map<String, Object> attributes) {
    this.attributes = attributes;
  }

  public String getProviderId() {
    return (String) attributes.get("sub");
  }

  public String getEmail() {
    return (String) attributes.get("email");
  }

  public String getName() {
    return (String) attributes.get("name");
  }
}
