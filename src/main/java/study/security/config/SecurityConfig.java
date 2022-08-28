package study.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/*
    -> WebSecurityConfigurerAdapter (핵심 웹 보안 기능 초기 화 및 설정)
    -> HttpSecurity (세부적인 보안 기능 설정할 수 있는 API 제공)

   흐름
   SpringSecurity가 HttpSecurity를 호출함
   내부에 filter, header, sessinMnagement, requestCache 등으 여러가지 설정 초기화

   단, 스프링 시큐리티 5.7ㅂ전 이후 WebSecurityConfigurerAdpter가 Depreacred되었다.
*/

/*
EnableWebSecurity에서 WebSecurity간련 클래스를 임포트하고 있기 대문에 반드시 추가해야함
@Import({ WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class,
		HttpSecurityConfiguration.class })
* */


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    /*
    * {noop} 패스워드 생성 방식 지정하지 않으면 사용 불가
    * */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() // 요청에 대한 보안 검사 실행
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN") // 위아래 순서 바꾸면 이건 아무 의미 없어짐(위에서부터 인증을 시도함)
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated(); // 모든 요청에 대해 검사 실행, 인증이 안되면 로그인 페이지로 리다이렉트

        http
                .formLogin()  // 폼 로그인 방식 사용
//                .loginPage("/loginPage") // 로그인 페이지 변경 가능
                .defaultSuccessUrl("/") // 로그인 성공시 이동할페이지
                .failureUrl("/login") // 로그인 실패시 이동할 페이지
                .usernameParameter("userId")
                .passwordParameter("passwd") // 로그인 파라미터명 변경 가능
                .loginProcessingUrl("/login_proc") // form태그 액션 url
                /*          .successHandler(
                                  new AuthenticationSuccessHandler() { // 성공시 핸들러
                              @Override
                              public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                  System.out.println("autehtication : " + authentication.getName() ); // 사용자명 출력 후 루트페이지로 이동
                                  response.sendRedirect("/");
                              }
                          })
                          .failureHandler(
                                  new AuthenticationFailureHandler() {
                                      @Override
                                      public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                          System.out.println("exeption : " + exception.getMessage()); // 실패 메세지 출력 후 로그인 페이지로 이동
                                          response.sendRedirect("/login");
                                      }
                                  }
                          )*/
                .permitAll(); // 해당 경로는 인증을 받지 않아도 된다.

        http
                .logout() // 기본적으로 시큐리티는 로그아웃을 포스트로만 가능함(처리 가능)
                .logoutUrl("/logout") // 로그아웃 후 페이지
                .logoutSuccessUrl("/login")
                .addLogoutHandler(
                        new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession session = request.getSession();
                                session.invalidate();// 세션 무효화
                            }
                        }
                )
                .logoutSuccessHandler(
                        new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/login");
                            }
                        }
                )
                .deleteCookies("remeber-me") // 서버에서 만든 쿠키 삭제
        ;

        http
                .rememberMe()
//                .rememberMeParameter("remember") // 리멤버 파라미터명 변경
//                .tokenValiditySeconds(3600) // 기본값 14일
                .userDetailsService(userDetailsService); // 유저 정보를 가져오는 인터페이스(return UserDetails)
        // 쿠키가 있다면 쿠키 값을 디코딩, 파싱, 추출해서 (필터에서) 인증함

        http
                .sessionManagement()
                .maximumSessions(1) // 최대 허용 가능 세션 수, -1일 경우 무제한 허용
                .maxSessionsPreventsLogin(true)  // 동시 로그인 차단, false일 경우 기존 세션을 만료시킴
                .expiredUrl("/login"); // 세션 만료시 이동할 페이지

        http
                .sessionManagement()
                .sessionFixation().changeSessionId(); // 기본값, 인증 시마다 세션 아이디, 쿠키를 새로 발급함
//                .sessionFixation().none(); // 세션 아이디가 새롭게 접속해도 계속 유지되어 취약점 발생
        // 공격자가 인증 전 사용자에게 쿠키 삽입, 공격자가 로그인 시 세션 아이디 생성되어 공격자와 공유 가능
    }
}