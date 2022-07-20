package dev.mkk7.security1.model;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.CreationTimestamp;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Table(name = "users")
@Entity
@Data
@NoArgsConstructor
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;
	private String username;
	private String password;
	private String email;
	private String role; // ROLE_USER, ROLE_ADMIN
	
	// 일반사용자인지 OAuth 로그인 한 사용자인지 구분하기 위함
	private String provider; 
	private String providerId;
	// 일반사용자인지 OAuth 로그인 한 사용자인지 구분하기 위함
	
	private Timestamp loginDate;
	@CreationTimestamp
	private Timestamp createDate;
	
	@Builder
	public User( String username, String password, String email, String role, String provider, String providerId,
			Timestamp loginDate, Timestamp createDate) {
		this.username = username;
		this.password = password;
		this.email = email;
		this.role = role;
		this.provider = provider;
		this.providerId = providerId;
		this.loginDate = loginDate;
		this.createDate = createDate;
	}
	
	
}
