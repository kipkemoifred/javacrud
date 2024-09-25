//package com.example.demo.config;
//
//import com.example.demo.entity.User;
//import io.jsonwebtoken.*;
//import jakarta.servlet.http.HttpServletRequest;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//import java.util.*;
//import java.util.concurrent.TimeUnit;
//import java.util.function.Function;
//@Component
//public class JwtUtil {
//    private static final String SECRET_KEY = "qwertyuiopasdfghjklzxcvbnm123456";
//    private static final long EXPIRATION_TIME = 86400000; // 1 day in milliseconds
//
//
//    private final JwtParser jwtParser;
//
//    private final String TOKEN_HEADER = "Authorization";
//    private final String TOKEN_PREFIX = "Bearer ";
//    public JwtUtil(){
//        this.jwtParser = Jwts.parser().setSigningKey(SECRET_KEY);
//    }
//
//
//    public JwtUtil(JwtParser jwtParser) {
//        this.jwtParser = jwtParser;
//    }
//
//    public String generateToken(UserDetails userDetails) {
//        Map<String, Object> claims = new HashMap<>();
//        return createToken(claims, userDetails.getUsername());
//    }
//
//    public String createToken(User user) {
//        Claims claims = Jwts.claims().setSubject(user.getEmail());
//        claims.put("firstName",user.getFirstName());
//        claims.put("lastName",user.getLastName());
//        Date tokenCreateTime = new Date();
//        Date tokenValidity = new Date(tokenCreateTime.getTime() + TimeUnit.MINUTES.toMillis(EXPIRATION_TIME));
//        return Jwts.builder()
//                .setClaims(claims)
//                .setExpiration(tokenValidity)
//                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
//                .compact();
//    }
//
//    private String createToken(Map<String, Object> claims, String subject) {
//        return Jwts.builder()
//                .setClaims(claims)
//                .setSubject(subject)
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
//                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
//                .compact();
//    }
//
//    public Boolean validateToken(String token, UserDetails userDetails) {
//        final String username = extractUsername(token);
//        System.out.println("extractUsername--" +username+" userDetails.getUsername() ---"+userDetails.getUsername());
//        return (username.equals(userDetails.getUsername()) );//&& !isTokenExpired(token)
//    }
//
//    private Boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    public Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }
//
//    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
//
//    private Claims extractAllClaims(String token) {
//        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
//    }
//
//
//
//    private Claims parseJwtClaims(String token) {
//        return jwtParser.parseClaimsJws(token).getBody();
//    }
//
//
//    public Claims resolveClaims(HttpServletRequest req) {
//        try {
//            String token = resolveToken(req);
//            if (token != null) {
//                return parseJwtClaims(token);
//            }
//            return null;
//        } catch (ExpiredJwtException ex) {
//            req.setAttribute("expired", ex.getMessage());
//            throw ex;
//        } catch (Exception ex) {
//            req.setAttribute("invalid", ex.getMessage());
//            throw ex;
//        }
//    }
//
//    public String resolveToken(HttpServletRequest request) {
//
//        String bearerToken = request.getHeader(TOKEN_HEADER);
//        if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
//            return bearerToken.substring(TOKEN_PREFIX.length());
//        }
//        return null;
//    }
//
//    public boolean validateClaims(Claims claims) throws AuthenticationException {
//        try {
//            return claims.getExpiration().after(new Date());
//        } catch (Exception e) {
//            throw e;
//        }
//    }
//}
