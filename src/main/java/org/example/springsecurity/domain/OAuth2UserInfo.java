package org.example.springsecurity.domain;

import java.util.Map;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class OAuth2UserInfo {

  private Map<String, Object> attributes;
  private String providerId;
  private String provider;
  private String email;
  private String name;

  public OAuth2UserInfo(String provider, Map<String, Object> attributes) {
    this.provider = provider;
    this.attributes = attributes;
  }

  public String getProviderId() {
    if (providerId == null) {
      return (String) attributes.get("sub");
    } else {
      return providerId;
    }
  }

  public String getEmail() {
    return (String) attributes.get("email");
  }

  public String getName() {
    return (String) attributes.get("name");
  }
}
