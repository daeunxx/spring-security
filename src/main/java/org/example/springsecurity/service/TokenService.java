package org.example.springsecurity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import org.example.springsecurity.domain.RoleType;
import org.example.springsecurity.domain.Token;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

  private final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

  public Token generateToken(String username, RoleType role) {
    // accessToken 10분, refreshToken 3주로 설정
    Long accessTokenPeriod = 1000L * 60L * 10L;
    Long refreshTokenPeriod = 1000L * 60L * 60L * 24L * 30L * 3L;

    // Claims에 사용하는 subject는 사용자를 구별하는 기본키
    // key-value 형태로 원하는 값 지정 가능
    Claims claims = Jwts.claims().setSubject(username);
    claims.put("role", role);

    Date now = new Date();

    return new Token(
        Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + accessTokenPeriod))
            .signWith(secretKey)
            .compact(), // 서명을 하기 위해 호출
        Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + refreshTokenPeriod))
            .signWith(secretKey)
            .compact());
  }

  /**
   * 토큰 다시 디코딩한 후, 유효기간이 지났는지 검증
   */
  public boolean verifyToken(String token) {
    try {
      Jws<Claims> claims = Jwts.parserBuilder()
          .setSigningKey(secretKey) // 디코딩
          .build().parseClaimsJws(token);
      return claims.getBody().getExpiration().after(new Date());
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * 토큰에 있는 subject 값 리턴
   */
  public String getUsername(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(secretKey)
        .build().parseClaimsJws(token)
        .getBody().getSubject();
  }

}
