package org.sid.secservice.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.sid.secservice.constant.JwtUtil;
import org.sid.secservice.entities.AppUser;
import org.sid.secservice.service.AuthService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class UserRestController {
    private AuthService authService;

    public UserRestController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/users")
    //@PostAuthorize("hasAuthority('USER')")
    public List<AppUser> getUsers() {
        return authService.getAllUser();
    }

    @PostMapping("/users")
    //@PostAuthorize("hasAuthority('ADMIN')")
    public AppUser addUser(@RequestBody AppUser user) {
        return authService.addUser(user);
    }

    @GetMapping("/profile")
    public AppUser getUserbyUsername(Principal principale) {
        return authService.findUserByUsername(principale.getName());
    }

    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationJwtToken = request.getHeader(JwtUtil.AUTH_HEADER);
        if (authorizationJwtToken != null && authorizationJwtToken.startsWith("Bearer ")) {
            try {
                String jwtToken = authorizationJwtToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtToken);
                String username = decodedJWT.getSubject();
                AppUser user = authService.findUserByUsername(username);
                String jwtAccessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(String.valueOf(System.currentTimeMillis() + JwtUtil.JWT_ACCESS_EXPIRE_DATE)))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",user.getRoles().stream().map(aut -> aut.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String,String> jwtMap = new HashMap<>();
                jwtMap.put("jwt-access",jwtAccessToken);
                jwtMap.put("jwt-refresh",jwtToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),jwtMap);

            } catch (Exception e) {
                response.setHeader("error-messsage", e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        } else {
             new RuntimeException("No Token Found!");
        }
    }
}
