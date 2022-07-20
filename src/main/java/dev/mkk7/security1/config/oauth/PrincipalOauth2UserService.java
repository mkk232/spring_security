package dev.mkk7.security1.config.oauth;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import dev.mkk7.security1.config.auth.Encrypt;
import dev.mkk7.security1.config.auth.PrincipalDetails;
import dev.mkk7.security1.config.oauth.provider.FacebookUserInfo;
import dev.mkk7.security1.config.oauth.provider.GoogleUserInfo;
import dev.mkk7.security1.config.oauth.provider.NaverUserInfo;
import dev.mkk7.security1.config.oauth.provider.OAuth2UserInfo;
import dev.mkk7.security1.model.User;
import dev.mkk7.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	@Autowired
	private Encrypt encrypt;

	@Autowired
	private UserRepository userRepository;

	// 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
	// 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어 진다.
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("getClientRegistration: " + userRequest.getClientRegistration()); // registration Id로 어떤
																								// OAuth로 로그인 했는지 확인 가능.
		System.out.println("getAccessToken: " + userRequest.getAccessToken().getTokenValue());

		OAuth2User oAuth2User = super.loadUser(userRequest);

		// 구글 로그인 버튼 클릭 -> 구글로그인창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리) ->
		// AccessToken 요청
		// userRequest 정보 -> 회원 프로필 받아야 함(loadUser 함수) -> 구글로 부터 회원 프로필 받아준다.
		System.out.println("getAttribute: " + super.loadUser(userRequest).getAttributes());

		// 회원가입을 강제로 진행해볼 예정
		OAuth2UserInfo oAuth2UserInfo = null;
		if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
		} else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
		} else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
			System.out.println("네이버 로그인 요청");
			oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
		} else {
			System.out.println("우리는 구글과 페이스북과 네이버만 지원해요 ㅎㅎ");
		}
//		String provider = userRequest.getClientRegistration().getRegistrationId(); // google
		String provider = oAuth2UserInfo.getProvider(); // google
		String providerId = oAuth2UserInfo.getProviderId();
		String email = oAuth2UserInfo.getEmail();
		String username = provider + "_" + providerId;
		String password = encrypt.encoderPWD().encode("겟인데어");
		String role = "ROLE_USER";

		User userEntity = userRepository.findByUsername(username);
		if (userEntity == null) {
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		}
		return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
	}
}
