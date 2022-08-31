package study.security.securitypack.provider;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import study.security.securitypack.common.FormWebAuthenticationDetails;
import study.security.securitypack.service.AccountContext;

public class CustomAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String inputId = authentication.getName();
        String inputPassword = (String) authentication.getCredentials();

        AccountContext findAccount = (AccountContext) userDetailsService.loadUserByUsername(inputId);

        if (!passwordEncoder.matches(inputPassword, findAccount.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }

        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = details.getSecretKey();

        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("예외");
        }

        return new UsernamePasswordAuthenticationToken(
                authentication.getPrincipal(), null, findAccount.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        // 유저네임 패스워드로 들어온 값이 DB와 일치할 때 인증 절차 진행한다
    }
}
