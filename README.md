# 1차 README
- 401 unauthorized 해결을 위한 Security 설정
- Datasource, JPA 설정
- Entity 설정
- H2 Console 결과 확인

## SecurityConfig
파일명 : `config/SecurityConfig.java`

`@EnableWebSecurity`
- 기본적인 웹 보안을 활성화 시킨다. 

추가적인 설정을 위해서 `WebSecurityConfigurer`를 implements 하거나, 
`WebSecurityConfigurerAdapter`를 extends 하는 방법이 있다.

여기서는 `WebSecurityConfigurerAdapter`를 extends 하는 방법으로 진행한다.
```java
// 1.

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
}

// 2.
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
    }
}

// 3.
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests() 
            .antMatchers("/api/hello").permitAll()
            .anyRequest().authenticated();
    }
}
```
`authorizeRequests()` : HttpServletRequest 를 사용하는 요청들에 대한 접근제한을 설정하겠다는 의미

`.antMatchers("/api/hello").permitAll()` : /api/hello 에 대한 요청은 인증 없이 접근을 허용하겠다는 의미이다.

`.anyRequest().authenticated()` : 나머지 요청들은 모두 인증되어야 한다는 의미

## application.yml
```yaml
spring:
  h2:
    console:
      enabled: true

  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password:

  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        format_sql: true
        show_sql: true

logging:
  level:
    me.silvernine: DEBUG
```
`database-platform: org.hibernate.dialect.H2Dialect` : H2 메모리 데이터베이스를 사용

`ddl-auto: create-drop` : create-drop 의 의미는 SessionFactory 가 시작될 때 Drop, Create, Alter 종료될때 Drop

## Entity
### User
```java
@Entity
@Table(name = "user")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {

   @JsonIgnore
   @Id
   @Column(name = "user_id")
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   private Long userId;

   @Column(name = "username", length = 50, unique = true)
   private String username;

   @JsonIgnore
   @Column(name = "password", length = 100)
   private String password;

   @Column(name = "nickname", length = 50)
   private String nickname;

   @JsonIgnore
   @Column(name = "activated")
   private boolean activated;

   @ManyToMany
   @JoinTable(
      name = "user_authority",
      joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "user_id")},
      inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")})
   private Set<Authority> authorities;
}
```
### Authority
```java
@Entity
@Table(name = "authority")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Authority {

   @Id
   @Column(name = "authority_name", length = 50)
   private String authorityName;
}
```

## data.sql
서버가 시작될 때마다 실행할 쿼리문을 넣는다.
```sql
INSERT INTO USER (USER_ID, USERNAME, PASSWORD, NICKNAME, ACTIVATED) VALUES (1, 'admin', '$2a$08$lDnHPz7eUkSi6ao14Twuau08mzhWrL4kyZGGU5xfiGALO/Vxd5DOi', 'admin', 1);
INSERT INTO USER (USER_ID, USERNAME, PASSWORD, NICKNAME, ACTIVATED) VALUES (2, 'user', '$2a$08$UkVvwpULis18S19S5pZFn.YHPZt3oaqHZnDwqbCW9pft6uFtkXKDC', 'user', 1);

INSERT INTO AUTHORITY (AUTHORITY_NAME) values ('ROLE_USER');
INSERT INTO AUTHORITY (AUTHORITY_NAME) values ('ROLE_ADMIN');

INSERT INTO USER_AUTHORITY (USER_ID, AUTHORITY_NAME) values (1, 'ROLE_USER');
INSERT INTO USER_AUTHORITY (USER_ID, AUTHORITY_NAME) values (1, 'ROLE_ADMIN');
INSERT INTO USER_AUTHORITY (USER_ID, AUTHORITY_NAME) values (2, 'ROLE_USER');
```

## SecurityConfig 세팅
SecurityConfig 에 H2 Database 에 접근을 원할하게 하기 위한 세팅

H2-console 하위 모든 요청들과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않도록 설정
```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
           .antMatchers("/h2-console/**", "/favicon.ico");
    }
    
   // ...
}

```
