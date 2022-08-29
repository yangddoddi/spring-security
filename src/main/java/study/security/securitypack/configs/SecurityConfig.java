package study.security.securitypack.configs;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Base64;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        String PASSWORD = passwordEncoder().encode("1111");

        auth.inMemoryAuthentication().withUser("user").password(PASSWORD).roles("USER","MANAGER","ADMIN");
        auth.inMemoryAuthentication().withUser("manager").password(PASSWORD).roles("MANAGER","ADMIN");
        auth.inMemoryAuthentication().withUser("admin").password(PASSWORD).roles("ADMIN");
    }

    @Override // WebIgnore 설정 : JS/CSS/Image 파일 등 보안 필터를 적용할 필요 없는 리소스 설정
    public void configure(WebSecurity web) throws Exception {
        web // 보안 필터 자체를 거치지 ㅇ낳
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // 정적 파일 통과
    }

    private PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated() // 모든 요청에 대해 인증 여부를 검사한다.
                .and()
                .formLogin(); // 인증되지 않았으면 formLogin화면으로
    }
}
