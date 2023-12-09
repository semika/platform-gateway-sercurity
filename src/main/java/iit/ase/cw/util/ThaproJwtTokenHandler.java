package iit.ase.cw.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import iit.ase.cw.model.Authority;
import iit.ase.cw.model.ThaproAuthentication;
import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.platform.common.security.model.AuthenticationRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

public class ThaproJwtTokenHandler {

    private String signedKey = "AGDFGDFGFVCXR";
    private ObjectMapper objectMapper = new ObjectMapper();

    public String generateToken(UserDetails userDetails) throws JsonProcessingException {
        return createToken(userDetails, userDetails.getUsername());
    }

    public String createToken(UserDetails userDetails, String subject) throws JsonProcessingException {
        return Jwts.builder()
            .claim(ThaproSecurityConstant.Security.THAPRO_USER_CLAIM, objectMapper.writeValueAsString(userDetails))
            .setSubject(subject) //username
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 *10 * 1000))
            .signWith(SignatureAlgorithm.HS512, signedKey) //key should be taken from a property file
            .compact();
    }

    public String generateClientToken(AuthenticationRequest authenticationRequest) throws JsonProcessingException {
        return Jwts.builder()
            .claim(ThaproSecurityConstant.Security.THAPRO_CLIENT_JWT, objectMapper.writeValueAsString(authenticationRequest))
            .setSubject(authenticationRequest.getUsername()) //username
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 *10 * 1000))
            .signWith(SignatureAlgorithm.HS512, signedKey) //key should be taken from a property file
            .compact();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(signedKey).parseClaimsJws(token).getBody();
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpirationDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Boolean isTokenExpired(String token) {
        return extractExpirationDate(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        String userName = extractUserName(token);
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public Authentication extractServerToken(String token) throws JsonProcessingException {
        Claims claims = extractAllClaims(token);
        String userJson = claims.get(ThaproSecurityConstant.Security.THAPRO_USER_CLAIM, String.class);

        String username  = claims.getSubject();

        //UserDetails userDetails = objectMapper.readValue(userJson, UserDetails.class);
        // Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) userDetails.getAuthorities();

        List<GrantedAuthority> authorities = new ArrayList<>();
        Authority authority1 = new Authority("ADMIN_USER");
        Authority authority2 = new Authority("FACILITY_USER");
        authorities.add(authority1);
        authorities.add(authority2);

        return new UsernamePasswordAuthenticationToken(
            username,
            null,
            authorities
        );
    }

    public AuthenticationRequest extractClientToken(String token) throws JsonProcessingException {
        Claims claims = extractAllClaims(token);
        String userJson = claims.get(ThaproSecurityConstant.Security.THAPRO_CLIENT_JWT, String.class);
        return objectMapper.readValue(userJson, AuthenticationRequest.class);
    }

    public String createToken(ThaproAuthentication authentication) throws JsonProcessingException {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, 10);
        Date validity = calendar.getTime();

        String thaproUserJson = objectMapper.writeValueAsString(authentication.getThaproUser());

        return Jwts.builder()
            .setSubject(authentication.getName())
            .claim(ThaproSecurityConstant.Security.THAPRO_USER_CLAIM, objectMapper.writeValueAsString(authentication))
            .signWith(SignatureAlgorithm.HS512, signedKey) //key should be taken from a property file
            .setExpiration(validity)
            .setIssuer("Thapro Software International Pvt Ltd")
            .compact();
    }

    public ThaproAuthentication getAuthentication(String token) throws JsonProcessingException {
//        Claims claims = Jwts.parserBuilder()
//            .setSigningKey(key)
//            .build()
//            .parseClaimsJws(token)
//            .getBody();

        Claims claims = extractAllClaims(token);

        String userJson = claims.get(ThaproSecurityConstant.Security.THAPRO_USER_CLAIM, String.class);

        return ThaproAuthentication.builder()
            .userName(claims.getSubject())
            .isAuthenticated(true)
            .thaproUser(objectMapper.readValue(userJson, ThaproAuthentication.class).getThaproUser())
            .build();
    }
}
