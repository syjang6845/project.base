package jsy.project.base.jwt;

import io.jsonwebtoken.*;
import jsy.project.base.entity.support.BaseUserRole;
import jsy.project.base.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Date;

@SpringBootTest
@Slf4j
public class TokenTest {

    @Autowired
    private JwtUtil jwtUtil;


    @Test
    @DisplayName("JWT access Token 발급")
    void accessTokenSuccess() {
        String jwt = jwtUtil.createAccessToken("user", "USER");

        Assertions.assertThat(jwt).isNotNull();

        Assertions.assertThat(jwtUtil.getUsername(jwt)).isEqualTo("user");
        Assertions.assertThat(jwtUtil.getRole(jwt)).isEqualTo(BaseUserRole.USER.name());
    }

    @Test
    @DisplayName("JWT Refresh Token 발급")
    void refreshTokenSuccess() {
        String jwt = jwtUtil.createAccessToken("user", "USER");

        Assertions.assertThat(jwt).isNotNull();

        Assertions.assertThat(jwtUtil.getUsername(jwt)).isEqualTo("user");
        Assertions.assertThat(jwtUtil.getRole(jwt)).isEqualTo(BaseUserRole.USER.name());
    }


    @Test
    @DisplayName("JWT Token 만료 되면 실패")
    void tokenExpiredFail() {
        String jwt = jwtUtil.createAccessToken("user", "USER");

        Assertions.assertThatThrownBy(() -> jwtUtil.isExpired(jwt)).isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    @DisplayName("시크릿키 변조되면 실패 만료 되면 실패")
    void notEqualsSecretKeyFail() {
        String jwt = Jwts.builder()
                .claim("username", "user")
                .claim("role", "USER")
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000L))
                .signWith(Jwts.SIG.HS256.key().build())
                .compact();

        Assertions.assertThatThrownBy(() -> jwtUtil.getUsername(jwt)).isInstanceOf(JwtException.class);
    }





    /**
     * Jwts.issuedAt 의 경우 밀리초 자리수를 버리기 떄문에 해당 메서드를 사용해야 합니다.
     * @param date
     * @return
     */
    private Date roundOffMillis(Date date) {
        return new Date(date.getTime() / 1000 * 1000);
    }
}
