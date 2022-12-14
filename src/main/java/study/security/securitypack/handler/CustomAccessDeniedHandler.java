package study.security.securitypack.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private String errorPage;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String deninedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();

        response.sendRedirect(deninedUrl);
    }

        public void setErrorPage(String eeror) {
            this.errorPage = errorPage;
        }
    }
