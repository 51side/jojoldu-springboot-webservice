package com.jojoldu.book.springboot.config.auth;

import com.jojoldu.book.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().headers().frameOptions().disable() //h2-console을 사용하기 위해 해당 옵션을 disable
                .and()
                    .authorizeRequests() //URL별 권한 관리를 설정하는 옵션의 시작점. 이걸 선언해야 antMatchers 옵션 사용 가능
                    .antMatchers("/", "/css/**", "/images/**", "/js/**","/h2-console/**").permitAll()
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                    .anyRequest().authenticated() //설정 값들 이외 나머지 URL. 인증사용자만 가능하도록.
                .and()
                    .logout().logoutSuccessUrl("/") //로그아웃 성공 시 이동 주소
                .and()
                    .oauth2Login().userInfoEndpoint().userService(customOAuth2UserService);
    }
}
