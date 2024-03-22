package org.example.springsecurity.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Entity
@Data
@Table(name = "users")
@Accessors(chain = true)
@NoArgsConstructor
public class User extends BaseEntity {

  @Id @GeneratedValue
  private Long id;
  private String username;
  private String password;
  private String email;
  private String provider;
  private String providerId;

  @Enumerated(EnumType.STRING)
  private RoleType role;
}
