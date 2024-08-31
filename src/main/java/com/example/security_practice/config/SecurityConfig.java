package com.example.security_practice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //로그인시 비밀번호에 대해 단방향 해시 암호화 진행, 저장 되어 있는 비밀번호와 대조,
    //회원가입시 비밀번호 항목에 대해 암호화 진행
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    //권한 A, 권한 B, 권한 C가 존재하고 권한의 계층은 “A < B < C”라고 설정을 진행하고 싶은 경우
    // RoleHierarchy 설정을 진행할 수 있다.
    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
                "ROLE_B > ROLE_A");

        return hierarchy;
    }


    //인메모리 방식
    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user1 = User.builder()
                .username("user1")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("ADMIN")
                .build();

        UserDetails user2 = User.builder()
                .username("user2")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

    /**
     *특정한 경로에 요청이 오면 Controller 클래스에 도달하기 전 필터에서 Spring Security가 검증을 함
     * 해당 경로의 접근은 누구에게 열려 있는지
     * 로그인이 완료된 사용자인지
     * 해당되는 role을 가지고 있는지
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );

        //특정 경로에 접근 권한이 없는 경우 자동으로 로그인 페이지로 리다이렉팅 되지 않고 오류 발생
        //Config 클래스를 설정하면 로그인 페이지 설정도 진행해야 한다.
        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .permitAll()
                );

        //개발 환경에서 csrf.disable -> 배포 환경에선 csrf 공격 방지를 위해 disable 설정 제거
        http
                .csrf((auth) -> auth.disable());

        //다중 로그인 설정
        http
                .sessionManagement((auth) -> auth
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true));
        /*
        maximumSession(정수) : 하나의 아이디에 대한 다중 로그인 허용 개수
        maxSessionPreventsLogin(불린) : 다중 로그인 개수를 초과하였을 경우 처리 방법
        true : 초과시 새로운 로그인 차단
        false : 초과시 기존 세션 하나 삭제

        sessionManagement
        sessionManagement().sessionFixation().none() : 로그인 시 세션 정보 변경 안함
        sessionManagement().sessionFixation().newSession() : 로그인 시 세션 새로 생성
        sessionManagement().sessionFixation().changeSessionId() : 로그인 시 동일한 세션에 대한 id 변경
         */

        //csrf 설정시 POST 요청으로 로그아웃 해야하지만, GET 방식으로 진행 가능
        http
                .logout((auth) -> auth.logoutUrl("/logout")
                        .logoutSuccessUrl("/"));

        //HTTPBASIC 인증
        //아이디와 비밀번호를 Base64 방식으로 인코딩한 뒤
        // HTTP 인증 헤더에 부착하여 서버측으로 요청을 보내는 방식이다
       // http
       //         .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
