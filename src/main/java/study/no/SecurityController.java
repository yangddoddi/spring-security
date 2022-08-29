package study.no;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

//@Slf4j
//@RestController
public class SecurityController {

    @GetMapping
    public String index() {
        return "home";
    }

    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "admin pay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }


    /*
    * HttpSession에서 접근 가능
    * SecurityContext에서 접근 가능
    * ThreadLocal에 저장되어 전역에서 참조 가능
    * */

    @GetMapping("/authentication")
    public String info(HttpSession session) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication2 = context.getAuthentication();

        boolean result = authentication2 == authentication;

        return String.valueOf(result);
    }

    /*
    * 저장 모드를 MODE_THREADLOCAL로 잡을 경우
    * 자깃 스레드에서 접급 불가능
    * */
    @GetMapping("/thread")
    public String thread() {
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    }
                }
        ).start();
        return "thread";
    }
}
