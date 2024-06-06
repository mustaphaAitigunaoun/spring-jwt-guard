package org.sid.secservice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthentificationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JwtAuthentificationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username =request.getParameter("username");
        String passsword = request.getParameter("password");
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username,passsword);
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
       User user = (User) authResult.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("mySecret");
//       String jwtAccessToken = JWT.create()
//               .withSubject(user.getUsername())
//               .withExpiresAt(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
//               .withIssuer(request.getRequestURL().toString())
//               .withClaim("roles",user.getAuthorities().stream().map(aut -> aut.getAuthority()).collect(Collectors.toList()))
//               .sign(algorithm);
       String JwtRefreshToken =  JWT.create()
               .withSubject(user.getUsername())
               .withExpiresAt(new Date(System.currentTimeMillis() + 15 * 60 * 1000))
               .withIssuer(request.getRequestURL().toString())
               .sign(algorithm);
       Map<String,String> jwtMap = new HashMap<>();
       jwtMap.put("jwt-access",jwtAccessToken);
       jwtMap.put("jwt-refresh",JwtRefreshToken);
       response.setContentType("application/json");
       new ObjectMapper().writeValue(response.getOutputStream(),jwtMap);
    }
}
