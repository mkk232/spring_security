package dev.mkk7.security1.config;

import javax.persistence.Embeddable;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import dev.mkk7.security1.config.auth.Encrypt;
import dev.mkk7.security1.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true,// secured 어노테이션 활성화
							prePostEnabled = true) // preAuthorize 활성화, postAuthorize 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
	@Autowired
	private Encrypt encrypt;
	
	/* 1. 코드를 받음 (인증이 되었다는 얘기)
	* 2. 엑세스 토큰 받음 (권한이 생김)
	* 3. 권한을 통해서 사용자 프로필 정보를 가져온다.
	* 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키도 함
	* 4-2. 그 정보가 모자랄 수 있음. -> 구글이 들고 있는 정보로 부족할 수 있음. 추가적인 정보가 필요할 수 있다. 
	*/
	
	// 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
//	@Bean
//	public BCryptPasswordEncoder encoderPWD() {
//		return new BCryptPasswordEncoder();
//	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
		.antMatchers("/user/**").authenticated() // user 경로는 인증이 되어야 하고
		.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // /manager 경로는 manager이나 admin 권한이 있어야 하고
		.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") // /admin 경로는 admin권한이 있어야 한다.
		.anyRequest().permitAll() // 다른 요청은 모두 허용한다.
		.and() // 그리고
		.formLogin() // 로그인이 필요하면
		.loginPage("/loginForm") // 로그인 페이지로 이동한다.
		.loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
		.defaultSuccessUrl("/") // 로그인이 성공하게 되면 기본으로 / 경로로 이동한다.
		.and()
		.oauth2Login()
		.loginPage("/loginForm") 
		.userInfoEndpoint()
		.userService(principalOauth2UserService); // 구글 로그인이 된 후 후처리가 필요함. TIP. 코드X, (엑세스 토큰 + 사용자 프로필 정보 O)
		
		
	}
}
