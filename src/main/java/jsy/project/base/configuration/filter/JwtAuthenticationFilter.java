package jsy.project.base.configuration.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jsy.project.base.dto.response.BaseUserToken;
import jsy.project.base.entity.BaseUser;
import jsy.project.base.entity.support.BaseUserRole;
import jsy.project.base.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static jsy.project.base.util.JwtUtil.*;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //request에서 Authorization 헤더를 찾음
        String authorization= request.getHeader(HttpHeaders.AUTHORIZATION);

        // Authorization 헤더가 없거나 Bearer로 시작하지 않으면, 리프레시 토큰을 쿠키에서 가져옵니다.
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            checkRefreshToken(request, response);
            filterChain.doFilter(request, response);
            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        // 액세스 토큰이 유효하면, 그 다음 사용자 인증 처리
        if (!jwtUtil.isExpired(token)) {
            setAuthentication(token);
        } else {
            // 액세스 토큰이 만료된 경우, 쿠키에서 리프레시 토큰을 가져오고 검증 후 새 액세스 토큰 발급
            checkRefreshToken(request, response);
        }
        filterChain.doFilter(request, response);
    }

    private void checkRefreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String refreshToken = getRefreshTokenFromCookies(request); // 쿠키에서 리프레시 토큰을 가져옵니다.
        log.info("check refresh token = {}", refreshToken);
        if (refreshToken != null && !jwtUtil.isExpired(refreshToken)) {
            // 리프레시 토큰이 유효한 경우, 새로운 액세스 토큰을 발급
            String newAccessToken = jwtUtil.refreshAccessToken(refreshToken);
            // 새로운 액세스 토큰을 응답에 추가 (헤더에 추가)
            // 기존 Authorization 헤더가 없는 경우에만 새 Authorization 헤더를 추가
            if (response.getHeader(HttpHeaders.AUTHORIZATION) == null) {
                response.setHeader(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + newAccessToken);
            } else {
                log.warn("Authorization header already exists, not setting a new one.");
            }
            setAuthentication(newAccessToken);
        } else {
            // 리프레시 토큰이 없거나 만료된 경우 Unauthorized 처리
            log.error("Invalid or expired refresh token.");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized
            response.getWriter().write("Unauthorized - Invalid or expired refresh token");
        }
    }

    private void setAuthentication(String token) {
        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        BaseUser userEntity = new BaseUser(username, "temppassword", BaseUserRole.fromString(role));

        //UserDetails에 회원 정보 객체 담기
        BaseUserToken userDetails = new BaseUserToken(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (REFRESH_TOKEN_PREFIX.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
