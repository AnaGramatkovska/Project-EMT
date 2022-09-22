package finki.project.weatherapp.controller;

import finki.project.weatherapp.entity.AppUser;
import finki.project.weatherapp.entity.ERole;
import finki.project.weatherapp.entity.Role;
import finki.project.weatherapp.payload.request.LoginRequest;
import finki.project.weatherapp.payload.request.SignupRequest;
import finki.project.weatherapp.payload.response.JwtResponse;
import finki.project.weatherapp.payload.response.MessageResponse;
import finki.project.weatherapp.security.AppUserDetails;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import finki.project.weatherapp.repository.AppUserRepository;
import finki.project.weatherapp.repository.RoleRepository;
import finki.project.weatherapp.security.jwt.JwtUtils;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/authentication")
public class AuthenticationController {

    private AuthenticationManager authenticationManager;

    private AppUserRepository appUserRepository;

    private RoleRepository roleRepository;

    private JwtUtils jwtUtils;

    public AuthenticationController(AuthenticationManager authenticationManager, AppUserRepository appUserRepository, RoleRepository roleRepository, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.appUserRepository = appUserRepository;
        this.roleRepository = roleRepository;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(
                        new UsernamePasswordAuthenticationToken(
                                loginRequest.getUsername(),
                                loginRequest.getPassword()
                        )
                );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        AppUserDetails appUserDetails = (AppUserDetails) authentication.getPrincipal();

        List<String> roles = appUserDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(
                new JwtResponse(
                        jwt,
                        appUserDetails.getId(),
                        appUserDetails.getUsername(),
                        roles
                )
        );
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {

        if (appUserRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error - Username is already taken!"));
        }

        AppUser appUser = new AppUser(
                signupRequest.getUsername(),
                signupRequest.getPassword()
        );

        Set<Role> roles = new HashSet<>();
        Set<String> stringRoles = signupRequest.getRole();

        if (stringRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error Role is not found"));
            roles.add(userRole);
        } else {
            for (String role : stringRoles) {
                if ("ROLE_ADMIN".equals(role)) {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);
                } else {
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
                }
            }
        }

        appUser.setRoles(roles);
        appUserRepository.save(appUser);

        return ResponseEntity.ok(
                new MessageResponse("Registration successful!")
        );
    }
}