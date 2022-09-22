package finki.project.weatherapp.security.jwt;

import finki.project.weatherapp.security.AppUserDetails;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration.ms}")
    private int jwtExpirationMilliseconds;

    public String generateJwtToken(Authentication authentication){

        AppUserDetails userPrincipal = (AppUserDetails) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMilliseconds))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUsernameFromJwtToken(String token){
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateJwtToken(String authenticationToken){
        try{
            Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(authenticationToken);
            return true;
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: ", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: ", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: ", e.getMessage());
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: ", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: ", e.getMessage());
        }
        return false;
    }

}
