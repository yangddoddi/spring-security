package study.security.securitypack.configs;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.security.filter.AjaxLoginProcessingFilter;
import study.security.securitypack.common.AjaxLoginAccessDeniedHandler;
import study.security.securitypack.common.AjaxLoginAuthenticationEntryPoint;
import study.security.securitypack.handler.AjaxAuthenticationFailurHander;
import study.security.securitypack.handler.AjaxAuthenticationSuccessHandler;
import study.security.securitypack.provider.AjaxAuthenticationProvider;

@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;

    public AjaxSecurityConfig(@Qualifier("ajax") AuthenticationSuccessHandler authenticationSuccessHandler, @Qualifier("ajax") AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
    }


    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager());
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
        return ajaxLoginProcessingFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Bean
    AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }

//    @Bean
//    AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return new AjaxAuthenticationSuccessHandler();
//    }

    @Bean
    AuthenticationFailureHandler authenticationFailureHandler() {
        return new AjaxAuthenticationFailurHander();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages")
                .hasRole("MANAGER")
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)  // 기존 필터보다 앞에서 필터 검사
                ;

        http
                .csrf().disable();

        http
                .exceptionHandling()
                .accessDeniedHandler(new AjaxLoginAccessDeniedHandler())
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint());

    }
}
