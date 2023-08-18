package io.github.ezbuild.filter;

import io.github.ezbuild.anno.SkipAuthentication;
import io.github.ezbuild.support.JWTToken;
import io.github.ezbuild.util.JWTUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.lang.annotation.Annotation;


/**
 * @author sheldon
 * @date 2023-08-17
 */
public class JWTFilter extends BasicHttpAuthenticationFilter {

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        return new JWTToken(getAuthzHeader(request));
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        WebApplicationContext ctx = RequestContextUtils.findWebApplicationContext(httpRequest);
        RequestMappingHandlerMapping mapping = ctx.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
        HandlerExecutionChain handler = null;
        try {
            handler = mapping.getHandler(httpRequest);
            Annotation[] declaredAnnotations = ((HandlerMethod) handler.getHandler()).getMethod().getDeclaredAnnotations();
            if (declaredAnnotations.length != 0) {
                for (Annotation annotation : declaredAnnotations) {
                    if (SkipAuthentication.class.equals(annotation.annotationType())) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return super.isAccessAllowed(request, response, mappedValue);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        boolean hasLogin = false;
        if (attemptLogin(request)) {
            hasLogin = executeLogin(request, response);
        }
        if (!hasLogin) {
            //throw biz exception
        }
        return hasLogin;
    }

    protected boolean attemptLogin(ServletRequest request) {
        String authzHeader = getAuthzHeader(request);
        return authzHeader != null && JWTUtils.verify(authzHeader,"");
    }

}
