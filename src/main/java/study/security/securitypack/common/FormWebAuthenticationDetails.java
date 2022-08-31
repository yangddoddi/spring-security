package study.security.securitypack.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

//@Component
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {
    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        request.getParameter("secret_key");
    }

    public String getSecretKey() {
        return secretKey;
    }
}
