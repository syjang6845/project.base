package jsy.project.base.util;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class JwtUtil {
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String REFRESH_TOKEN_PREFIX = "refreshToken";
//    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 60 * 60 * 1000L; // 1시간 (60초 * 60분 * 1000밀리초)
    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 5 * 1000;
    private static final long REFRESH_TOKEN_EXPIRATION_TIME = 60 * 60 * 24 * 30 * 1000L; // 30일 (60초 * 60분 * 24시간 * 30일 * 1000밀리초)
    private final SecretKey secretKey;

    public JwtUtil(@Value("${jwt.secret.key}")String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 리프레시 토큰을 사용해 새로운 액세스 토큰 발급
    public String refreshAccessToken(String refreshToken) {
        // 리프레시 토큰 검증
        Claims claims = validateToken(refreshToken);
        // 리프레시 토큰이 유효하면 새로운 액세스 토큰 발급
        String username = claims.get("username", String.class);
        String role = claims.get("role", String.class);

        // 새로운 액세스 토큰 발급
        return createAccessToken(username, role);
    }

    public String createRefreshToken(String username, String role) {
        return createToken(username, role, REFRESH_TOKEN_EXPIRATION_TIME);
    }

    public String createAccessToken(String username, String role) {
        return createToken(username, role, ACCESS_TOKEN_EXPIRATION_TIME);
    }

    public String createAccessTokenWithTime(String username, String role, Long time) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(time))
                .expiration(new Date(time + ACCESS_TOKEN_EXPIRATION_TIME))
                .signWith(secretKey)
                .compact();
    }


    public String getUsername(String token) {
        return validateToken(token).get("username", String.class);
    }

    public String getRole(String token) {
        return validateToken(token).get("role", String.class);
    }

    public Boolean isExpired(String token) {
        try {
            return validateToken(token).getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            // ExpiredJwtException 발생 시, 로그를 찍고, 만료된 토큰으로 간주하여 false 반환
            log.error("Token expired: {}", e.getMessage());
            return true; // 토큰이 만료된 것으로 간주
        } catch (SecurityException e) {
            // SecurityException 발생 시, 토큰 서명이 올바르지 않음
            log.error("Invalid JWT signature: {}", e.getMessage());
            return false; // 서명 문제로 유효하지 않은 토큰으로 간주
        } catch (JwtException e) {
            // JwtException 발생 시, 일반적인 JWT 오류 처리
            log.error("Invalid JWT Token: {}", e.getMessage());
            return false; // 잘못된 토큰으로 간주
        }
    }

    // ✅ JWT 검증 메서드
    public Claims validateToken(String token) {
        try {
            // ✅ 내부 시크릿 키로 검증
            return Jwts.parser()
                    .verifyWith(secretKey) // ✅ 내부 시크릿 키로 검증
                    .build()
                    .parseSignedClaims(token)
                    .getPayload(); // ✅ 유효한 경우 클레임 반환
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException(e.getHeader(), e.getClaims(), "Token expired");
        } catch (SecurityException e) {
            throw new SecurityException("Invalid JWT signature: Token may be tampered with", e);
        } catch(JwtException e) {
            throw new JwtException("Invalid JWT Token", e);
        }
    }

    private String createToken(String username, String role, Long expiredTime) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredTime))
                .signWith(secretKey)
                .compact();
    }
}
