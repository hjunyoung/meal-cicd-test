package com.example.mealserve.global.security.filter;


import com.example.mealserve.domain.account.dto.LoginRequestDto;
import com.example.mealserve.domain.account.entity.AccountRole;
import com.example.mealserve.global.security.impl.UserDetailsImpl;
import com.example.mealserve.global.security.jwt.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j(topic = "로그인 및 JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
        setFilterProcessesUrl("/api/auth/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        log.info("로그인 시도");

        try {
            LoginRequestDto requestDto = objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);

            log.info("Email: {}", requestDto.getEmail());

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            requestDto.getEmail(),
                            requestDto.getPassword(),
                            null
                    )
            );

        } catch (IOException | AuthenticationException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
            throws IOException {

        log.info("로그인 성공 및 JWT 생성");

        String email = ((UserDetailsImpl) authResult.getPrincipal()).getUsername();
        AccountRole role = ((UserDetailsImpl) authResult.getPrincipal()).getAccount().getRole();

        String token = jwtUtil.createToken(email, role);

        // 성공 메시지와 토큰을 JSON 형식으로 응답에 추가
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse("로그인 성공", email, role )));
        response.setStatus(HttpServletResponse.SC_OK);

        jwtUtil.addJwtToCookie(token, response);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed)
            throws IOException {

        log.info("로그인 실패: {}", failed.getMessage());

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(new ErrorResponse("로그인 실패")));
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    // 간단한 응답 객체
    @Getter
    private static class SimpleResponse {
        private final String message;
        private final String email;
        private final AccountRole role;

        public SimpleResponse(String message, String email, AccountRole role) {
            this.message = message;
            this.email = email;
            this.role = role;
        }
    }

    @Getter
    private static class ErrorResponse {
        private final String message;

        public ErrorResponse(String message) {
            this.message = message;
        }
    }
}
