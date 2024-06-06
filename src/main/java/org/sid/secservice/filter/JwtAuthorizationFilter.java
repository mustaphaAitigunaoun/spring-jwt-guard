package org.sid.secservice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getContextPath().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        }else {
            String authorizationJwtToken =  request.getHeader("Authorization");
            if(authorizationJwtToken != null && authorizationJwtToken.startsWith("Bearer ")){
                try {
                    String jwtToken = authorizationJwtToken.substring(7);
                    Algorithm algorithm = Algorithm.HMAC256("mySecret");
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwtToken);
                    String username = decodedJWT.getSubject();
                    List<String> roles = decodedJWT.getClaim("roles").asList(String.class);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for(String r : roles) {
                        authorities.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(username,null,authorities);
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    filterChain.doFilter(request,response);
                }catch(Exception e) {
                    response.setHeader("error-messsage",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }else {
                filterChain.doFilter(request,response);
            }
        }


    }
}
