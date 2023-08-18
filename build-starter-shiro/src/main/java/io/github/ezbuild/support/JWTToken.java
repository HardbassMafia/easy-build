package io.github.ezbuild.support;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.apache.shiro.authc.AuthenticationToken;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;

/**
 * @author sheldon
 * @date 2023-08-17
 */
@RequiredArgsConstructor
public class JWTToken implements AuthenticationToken {

    private final String token;

    @Override
    public Object getPrincipal() {
        return this.token;
    }

    @Override
    public Object getCredentials() {
        return this.token;
    }

}
