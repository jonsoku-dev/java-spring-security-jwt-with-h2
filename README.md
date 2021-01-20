- 401 unauthorized 해결을 위한 Security 설정
- Datasource, JPA 설정
- Entity 설정
- H2 Console 결과 확인

# SecurityConfig
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

# application.yml
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
