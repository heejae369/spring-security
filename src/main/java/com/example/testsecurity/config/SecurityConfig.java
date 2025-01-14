package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{

        // 해당경로(관리자, 일반유저, 로그인이 필요한 요청 등) 얼마나 open할지 설정
        httpSecurity
            //특정 경로 요청 허용, 거부
            .authorizeHttpRequests((auth) -> auth
                .requestMatchers("/", "/login").permitAll()// 해당 요청 경로는 모두 open
                .requestMatchers("/admin").hasRole("ADMIN") // ADMIN 롤을 가짐
                .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")// 유저 아이디(와일드카드 : ** ), 여러 롤 설정
                .anyRequest().authenticated()// anyRequest(): 위의 경로 외 나머지, authenticated(): 로그인한 사용자만 접근
            );
        return httpSecurity.build();
    }
}
