package com.mohamed.securityservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private String secretKey;
    private Long jwtExpiration;

    public String extractUsername(String token) {
        return extraClaim(token, Claims::getSubject);
    }

    public <T> T extraClaim(String token, Function<Claims, T> claimsResolver) {

        Claims claims=extracAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extracAllClaims(String token) {
        return  Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }



    private Key getSigningKey() {
         byte[] bytes= Decoders.BASE64.decode(secretKey);
         return Keys.hmacShaKeyFor(bytes);
    }

    public String generateToken(UserDetails userDetails){
        return generatedTokenWithClaims(new HashMap<>(),userDetails);
    }

    public String generatedTokenWithClaims(Map<String,Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims,userDetails,jwtExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            Long jwtExpiration) {

        var authorities=userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

            return Jwts
                    .builder()
                    .setSubject(userDetails.getUsername())
                    .setClaims(extraClaims)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                    .claim("authorities",authorities)
                    .signWith(getSigningKey())
                    .compact()

        ;
    }


    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username=extractUsername(token);
     return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractJwtExpiration(token).before(new Date());
    }

    private Date extractJwtExpiration(String token) {
        return extraClaim(token,Claims::getExpiration);
    }
}
