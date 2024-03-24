package org.example.springsecurity.domain;

import java.util.Map;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
@Builder(access = AccessLevel.PRIVATE)
public class OAuth2Attribute {

  private Map<String, Object> attributes;
  private String provider;
  private String providerId;
  private String username;
  private String email;

  public static OAuth2Attribute of(String provider, String attributeKey, Map<String, Object> attributes) {
    switch (provider) {
      case "google":
        return ofGoogle(provider, attributeKey, attributes);
      case "naver":
        return ofNaver(provider, attributeKey, attributes);
      default:
        throw new RuntimeException();
    }
  }

  private static OAuth2Attribute ofGoogle(String provider, String attributeKey,
      Map<String, Object> attributes) {
    return OAuth2Attribute.builder()
        .attributes(attributes)
        .provider(provider)
        .providerId((String) attributes.get(attributeKey))
        .email((String) attributes.get("email"))
        .build();
  }

  private static OAuth2Attribute ofNaver(String provider, String attributeKey,
      Map<String, Object> attributes) {
    Map<String, Object> naverAttributes = (Map<String, Object>) attributes.get(attributeKey);

    return OAuth2Attribute.builder()
        .attributes(naverAttributes)
        .provider(provider)
        .providerId((String) naverAttributes.get("id"))
        .email((String) naverAttributes.get("email"))
        .build();
  }

  public String getUsername() {
    return this.provider + "_" + this.providerId;
  }
}
