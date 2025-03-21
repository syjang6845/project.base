package jsy.project.base.util;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    private static final String BEARER_PREFIX = "Bearer "; //
    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 60 * 60 * 1000L; // 1시간 (60초 * 60분 * 1000밀리초)
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
        return BEARER_PREFIX + createToken(username, role, ACCESS_TOKEN_EXPIRATION_TIME);
    }

    public String getUsername(String token) {
        return validateToken(token).get("username", String.class);
    }

    public String getRole(String token) {
        return validateToken(token).get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return validateToken(token).getExpiration().before(new Date());
    }

    // ✅ JWT 검증 메서드
    private Claims validateToken(String token) {
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
