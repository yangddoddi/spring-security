package study.security.securitypack.configs;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import study.security.filter.AjaxLoginProcessingFilter;
import study.security.repository.UserRepository;
import study.security.securitypack.handler.CustomAccessDeniedHandler;
import study.security.securitypack.handler.CustomAuthenticationSuccessHandler;
import study.security.securitypack.provider.CustomAuthenticationProvider;
import study.security.securitypack.service.CustomUserDetailsService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

@Configuration
@EnableWebSecurity
@Slf4j
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    public SecurityConfig(AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource, UserDetailsService userDetailsService, UserRepository userRepository, @Qualifier("form") AuthenticationSuccessHandler successHandler, @Qualifier("form") AuthenticationFailureHandler failureHandler) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        String PASSWORD = passwordEncoder().encode("1111");
//
//        auth.inMemoryAuthentication().withUser("user").password(PASSWORD).roles("USER","MANAGER","ADMIN");
//        auth.inMemoryAuthentication().withUser("manager").password(PASSWORD).roles("MANAGER","ADMIN");
//        auth.inMemoryAuthentication().withUser("admin").password(PASSWORD).roles("ADMIN");
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService); // 내가 만든 userDetailService를 이용해서 인증처리하게 됨
        auth.authenticationProvider(customAuthenticationProvider()); // 커스텀 프로바이더일 경우에만 직접 지정해주면 됨(위와 같다)
    }

    @Override // WebIgnore 설정 : JS/CSS/Image 파일 등 보안 필터를 적용할 필요 없는 리소스 설정
    public void configure(WebSecurity web) throws Exception {
        web // 보안 필터 자체를 거치지 ㅇ낳
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // 정적 파일 통과
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }


    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider(userDetailsService(),passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","user/login/**,/login*,/login?error*").permitAll()
                .antMatchers("/users").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated() // 모든 요청에 대해 인증 여부를 검사한다.

                .and()
                .formLogin() // 인증되지 않았으면 formLogin화면으로
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("실패");
//                        response.sendRedirect("/login");
//                    }
//                })
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll()

                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());
    }
}
