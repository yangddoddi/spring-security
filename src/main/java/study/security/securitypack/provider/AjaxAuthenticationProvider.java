package study.security.securitypack.provider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import study.security.securitypack.common.FormWebAuthenticationDetails;
import study.security.securitypack.service.AccountContext;
import study.security.securitypack.token.AjaxAuthenticationToken;

import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String inputId = authentication.getName();

        String inputPassword = (String) authentication.getCredentials();

        Optional<AccountContext> userDetails = Optional.ofNullable((AccountContext)userDetailsService.loadUserByUsername(inputId));
        AccountContext findAccount = userDetails.orElseThrow(() -> {
            return new RuntimeException("왜안딤");
        });

        if (!passwordEncoder.matches(inputPassword, findAccount.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }

        return new AjaxAuthenticationToken(
                findAccount.getAccount(), authentication.getCredentials(), findAccount.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
        // 해당 유형의 토큰을 받았을 때 이 프로바이더가 동작한다
    }
}
