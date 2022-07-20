package dev.mkk7.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import dev.mkk7.security1.config.auth.Encrypt;
import dev.mkk7.security1.config.auth.PrincipalDetails;
import dev.mkk7.security1.model.User;
import dev.mkk7.security1.repository.UserRepository;

@Controller
public class IndexController {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private Encrypt encrypt;
	
	@GetMapping("/test/login")
	public @ResponseBody String testLogin(
			Authentication authentication,
			@AuthenticationPrincipal PrincipalDetails userDetails) { // DI(의존성주입)
		
		System.out.println("/test/login =================");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication : " + principalDetails.getUser());
		System.out.println("userDetails : " + userDetails.getUser());
		
		return "세션 정보 확인하기";
	}
	
	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) { // DI(의존성주입)
		
		System.out.println("/test/login =================");
		OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication : " + oAuth2User.getAttributes());
		
		System.out.println("oauth2User : " + oauth.getAttributes());
		return "OAuth 세션 정보 확인하기";
	}
	
	@GetMapping({"","/"})
	public String index() {
		return "index";
	}
	
	// OAuth 로그인을 해도 PrincipalDetails 
	// 일반 로그인을 해도 PrincipalDetails
	@GetMapping("/user")			
	public @ResponseBody String user(@AuthenticationPrincipal /*  */PrincipalDetails principalDetails) {
		System.out.println("principalDetails : " + principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	// Spring security가 해당 주소를 낚아챈다. - SecurityConfig 파일 생성 후 작동안함.
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		System.out.println(user);
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = encrypt.encoderPWD().encode(rawPassword);
		user.setPassword(encPassword);
		userRepository.save(user); // 회원가입 잘 됨. 비밀번호 : 1234 -> 시큐리티로 로그인 할 수 없음. 이유는 패스워드가 암호화가 안되었기 때문이다.
		return "redirect:/loginForm";
	}
	
	@Secured("ROLE_ADMIN") // SecurityConfig 파일에서 @EnableGlobalMethodSecurity를 설정해놓음. 특정 메소드에 권한을 걸고 싶을 때
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}

	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // data메서드가 실행되기 직전에 실행이 됨 (Secured와 같은데 여러개를 걸고 싶을 때)
//	@PostAuthorize() // data 메서드가 실행된 후 실행
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터정보";
	}
	
}












