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
# 2차 README
* JWT 설정 추가
* JWT 관련 코드 개발
* JWT 관련 Security Config 설정 추가

## JWT 설정 추가
### build.gradle
```groovy
compile group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.11.2'
runtime group: 'io.jsonwebtoken', name: 'jjwt-impl', version: '0.11.2'
runtime group: 'io.jsonwebtoken', name: 'jjwt-jackson', version: '0.11.2'
```
### application.yml
```yaml
...

jwt:
  header: Authorization
  #HS512 알고리즘을 사용할 것이기 때문에 512bit, 즉 64byte 이상의 secret key를 사용해야 한다.
  #echo 'silvernine-tech-spring-boot-jwt-tutorial-secret-silvernine-tech-spring-boot-jwt-tutorial-secret'|base64
  secret: c2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQtc2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQK
  token-validity-in-seconds: 86400

...
```

## JWT 관련 코드 개발
* jwt 라는 패키지를 하나 만든다.
* 토큰의 생성, 토큰의 유효성 검증등을 담당할 Token Provider 를 만들어보자
### jwt/TokenProvider.java
```java
@Component
public class TokenProvider implements InitializingBean {

   private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

   private static final String AUTHORITIES_KEY = "auth";

   private final String secret;
   private final long tokenValidityInMilliseconds;

   private Key key;


   public TokenProvider(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
      this.secret = secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
   }

   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(secret);
      this.key = Keys.hmacShaKeyFor(keyBytes);
   }

   public String createToken(Authentication authentication) {
      String authorities = authentication.getAuthorities().stream()
         .map(GrantedAuthority::getAuthority)
         .collect(Collectors.joining(","));

      long now = (new Date()).getTime();
      Date validity = new Date(now + this.tokenValidityInMilliseconds);

      return Jwts.builder()
         .setSubject(authentication.getName())
         .claim(AUTHORITIES_KEY, authorities)
         .signWith(key, SignatureAlgorithm.HS512)
         .setExpiration(validity)
         .compact();
   }

   public Authentication getAuthentication(String token) {
      Claims claims = Jwts
              .parserBuilder()
              .setSigningKey(key)
              .build()
              .parseClaimsJws(token)
              .getBody();

      Collection<? extends GrantedAuthority> authorities =
         Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

      User principal = new User(claims.getSubject(), "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
   }

   public boolean validateToken(String token) {
      try {
         Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         logger.info("잘못된 JWT 서명입니다.");
      } catch (ExpiredJwtException e) {
         logger.info("만료된 JWT 토큰입니다.");
      } catch (UnsupportedJwtException e) {
         logger.info("지원되지 않는 JWT 토큰입니다.");
      } catch (IllegalArgumentException e) {
         logger.info("JWT 토큰이 잘못되었습니다.");
      }
      return false;
   }
}
```
`afterPropertiesSet` : InitializingBean 을 implements 해서 afterPropertiesSet 을 Override 한 이유는 빈이 생성이 되고 주입을 받은 후에 secret 값을 Base64 Decode 해서 key 변수에 할당한다.

`createToken` : Authentication 객체의 권한정보를 이용해서 토큰을 생성하는 메소드. 이 함수는 jwt 토큰을 생성하여 리턴한다.

`getAuthentication` : Token 에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메소드. 토큰으로 클레임을 만들고 이를 이용해 유저 객체를 만들어서 최종적으로 Authentication 객체를 리턴한다.

`validateToken` : 토큰의 유효성 검증을 수행한다. 토큰을 받아 유효성에 따라 Boolean 을 리턴한다.

