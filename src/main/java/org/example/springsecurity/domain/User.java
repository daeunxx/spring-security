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
@NoArgsConstructor
@Accessors(chain = true)
public class User extends BaseEntity {

  @Id @GeneratedValue
  private Long id;
  private String username;
  private String password;
  private String email;
  @Enumerated(EnumType.STRING)
  private RoleType role;

  private String provider;
  private String providerId;
}
