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

## jwt/JwtFilter
JWT 를 위한 커스텀 필터를 만들기 위해 JwtFilter 클래스를 생성한다.
```java
public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String jwt = resolveToken(httpServletRequest);
        String requestURI = httpServletRequest.getRequestURI();

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
```
`GenericFilterBean` 을 extends 해서 doFilter 를 Override 한다. 실제 필터링 로직은 doFilter 내부에 작성한다.

`resolveToken` : Request Header 에서 토큰 정보를 꺼내오기 위한 resolveToken 메소드 추가.

`doFilter` : JWT 토큰의 인증정보 (resulveToken 으로부터 받은 정보) 를 SecurityContext 에 저장하는 역할을 수행한다.


 ## jwt/JwtSecurityConfig
 이전 만든 `TokenProvider` 및 `JwtFilter`를 SecurityConfig 에 적용할 때 사용할 JwtSecurityConfig 클래스 추가
 ```java
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final TokenProvider tokenProvider;

    public JwtSecurityConfig(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
 ```

## jwt/JwtAuthenticationEntryPoint
유효한 자격증명을 제공하지 않고 접근하려 할때, 401 Unauthorized 에러를 리턴할 JwtAuthenticationEntryPoint 클래스를 만든다.
```java
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // 유효한 자격증명을 제공하지 않고 접근하려 할때 401
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
```

## jwt/JwtAccessDeniedHandler
필요한 권한이 존재하지 않는 경우에 403 Forbidden 에러를 리턴하기 위해서 JwtAccessDeniedHandler 클래스를 만든다.
```java
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws
                                                                                                                              IOException {
        //필요한 권한이 없이 접근하려 할때 403
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}
```

## SecurityConfig 수정
### CorsConfig 추가
```java
@Configuration
public class CorsConfig {

   @Bean
   public CorsFilter corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();
      config.setAllowCredentials(true);
      config.addAllowedOrigin("*");
      config.addAllowedHeader("*");
      config.addAllowedMethod("*");

      source.registerCorsConfiguration("/api/**", config);
      return new CorsFilter(source);
   }

}
```

SecurityConfig 에 Jwt 관련 로직 추가
```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final CorsFilter corsFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            CorsFilter corsFilter,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.corsFilter = corsFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
           .antMatchers(
                   "/h2-console/**"
                   ,"/favicon.ico"
                   ,"/error"
           );
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
                .csrf().disable()

                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()

                .anyRequest().authenticated()

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}
```
`@EnableGlobalMethodSecurity` : @PreAuthorize 어노테이션을 메소드 단위로 추가하기 위해서 적용

`SecurityConfig` 는 TokenProvider, JwtAuthenticationEntryPoint, JwtAccessDeniedHandler 주입
 
`PasswordEncoder` : BCryptPasswordEncoder 를 사용한다.

`httpSecurity.csrf().disable()` : 토큰을 사용하기 때문에 csrf 설정은 disable 한다.

`.authenticationEntryPoint(jwtAuthenticationEntryPoint)` : Exception 을 핸들링하는 곳. 만들었던 파일을 집어 넣는다.

`.accessDeniedHandler(jwtAccessDeniedHandler)` : Exception 을 핸들링하는 곳. 만들었던 파일을 집어 넣는다.

`.sessionCreationPolicy(SessionCreationPolicy.STATELESS)` : 세션을 사용하지 않기 때문에 STATELESS 설정

`.antMatchers("/api/hello").permitAll()` : 해당 API 는 토큰이 없는 상태에서 들어오기 때문에 permitAll

`.antMatchers("/api/authenticate").permitAll()` : 해당 API 는 토큰이 없는 상태에서 들어오기 때문에 permitAll

`.antMatchers("/api/signup").permitAll()` : 해당 API 는 토큰이 없는 상태에서 들어오기 때문에 permitAll

`.apply(new JwtSecurityConfig(tokenProvider))` : JwtFilter 를 addFilter 로 등록했던, JwtSecurityConfig 클래스도 적용.
    
                
# 3차 README
* 외부와의 통신에 사용할 DTO 클래스 생성
* Repository 관련 코드 생성
* 로그인 API, 관련 로직 생성

## dto
외부와의 통신에 사용할 DTO 클래스 생성
### dto/LoginDto
```java
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto {

   @NotNull
   @Size(min = 3, max = 50)
   private String username;

   @NotNull
   @Size(min = 3, max = 100)
   private String password;
}
```
### dto/TokenDto
```java
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenDto {

    private String token;
}
```
### dto/UserDto
```java
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {

   @NotNull
   @Size(min = 3, max = 50)
   private String username;

   @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
   @NotNull
   @Size(min = 3, max = 100)
   private String password;

   @NotNull
   @Size(min = 3, max = 50)
   private String nickname;
}
```

## repository
### repository/UserRepository
`findOneWithAuthoritiesByUsername` : username 을 기준으로 User 정보를 가져올 때 권한 정보도 같이 가져오게 된다.
```java
public interface UserRepository extends JpaRepository<User, Long> {
   @EntityGraph(attributePaths = "authorities")
   Optional<User> findOneWithAuthoritiesByUsername(String username);
}
```

### repository/AuthorityRepository
```java
public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
```

## service
### service/CustomUserDetailsService
CustomUserDetailsService 는 `UserDetailsService` 를 주입 받는다.
`loadUserByUsername` 메소드를 오버라이드 해서 구현해야한다.
token 검증 시 필수메소드 : 로그인시에 DB 에서 유저정보와 권한 정보를 가져오게 된다. 해당 정보를 기반으로 userDetails.User 객체를 생성해서 리턴한다.
리턴되는 User 는 `org.springframework.security.core.userdetails.User` 의 User 이다. (spring security 객체) 
```java
@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
   private final UserRepository userRepository;

   public CustomUserDetailsService(UserRepository userRepository) {
      this.userRepository = userRepository;
   }

   @Override
   @Transactional
   public UserDetails loadUserByUsername(final String username) {
      return userRepository.findOneWithAuthoritiesByUsername(username)
         .map(user -> createUser(username, user))
         .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
   }

   private org.springframework.security.core.userdetails.User createUser(String username, User user) {
      if (!user.isActivated()) {
         throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
      }
      List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
              .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
              .collect(Collectors.toList());
      return new org.springframework.security.core.userdetails.User(user.getUsername(),
              user.getPassword(),
              grantedAuthorities);
   }
}
```

## Controller 
### controller/AuthController
1. AuthController 는 TokenProvider, AuthenticationManagerBuilder 를 주입 받는다. 로그인 API 경로는 `/api/authenticate` 이고 Post 요청을 받는다.
2. LoginDto 의 username, password 를 파라미터로 받고 이를 이용해 UsernamePasswordAuthenticationToken 을 생성한다.
3. authenticationToken 을 이용해서 Authentication 객체를 생성하려고 authenticate method 가 실행이 될 때 loadUserByUsername 메소드가 실행된다.
4. Authentication 객체를 생성하고 이를 SecurityContext 에 저장하고 Authentication 객체를 createToken 메소드를 통해서 JWT Token 을 생성한다.
5. JWT Token 을 Response Header 에도 넣어주고 TokenDto 를 이용해서 Response Body 에도 넣어서 리턴하게 된다.  

```java
@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}
```

# 4차 README
* 회원가입 API 생성
* 권한 검증 확인

## 유틸리티 메소드
### util/SecurityUtil
`getCurrentUsername` : Security Context 의 Authentication 객체를 이용해 username 을 리턴해주는 간단한 유틸성 메소드

Security Context 에 Authentication 객체가 저장되는 시점은 JwtFilter 의 doFilter 메소드에서 Request 가 들어올 때 SecurityContext 에 Authentication 객체를 저장해서 사용하게 된다.

```java
public class SecurityUtil {

    private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    private SecurityUtil() {
    }

    public static Optional<String> getCurrentUsername() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            logger.debug("Security Context에 인증 정보가 없습니다.");
            return Optional.empty();
        }

        String username = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            username = springSecurityUser.getUsername();
        } else if (authentication.getPrincipal() instanceof String) {
            username = (String) authentication.getPrincipal();
        }

        return Optional.ofNullable(username);
    }
}
```

## 회원가입을 위한 섭스
### service/UserService
UserService 는 UserRepository, PasswowrdEncoder 를 주입받는다.

`signup` : 회원가입 로직을 수행하는 메서드, username 이 DB 에 존재하지 않으면 Authority 와 User 정보를 생성해서 UserRepository 의 save 메소드를 통해 DB 에 정보를 저장한다.

첫번째 `getUserWithAuthorities` : username 을 기준으로 정보를 가져옴

두번째 `getUserWithAuthorities` : SecurityContext 에 저장 된 username 을 기준으로 정보를 가져옴 

```java
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        //빌더 패턴의 장점
        Authority authority = Authority.builder()
                                       .authorityName("ROLE_USER")
                                       .build();

        User user = User.builder()
                        .username(userDto.getUsername())
                        .password(passwordEncoder.encode(userDto.getPassword()))
                        .nickname(userDto.getNickname())
                        .authorities(Collections.singleton(authority))
                        .activated(true)
                        .build();

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
```

## UserController
### controller/UserContoller
`getMyUserInfo` : @PreAuthorize 를 통해서 USER, ADMIN 두가지 권한 모두 허용

`getUserInfo` : @PreAuthorize 를 통해서 ADMIN 권한만 허용

```java
@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("hello");
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signup(
            @Valid @RequestBody UserDto userDto
    ) {
        return ResponseEntity.ok(userService.signup(userDto));
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<User> getMyUserInfo() {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}
```
