package finki.project.weatherapp.configuration;

import finki.project.weatherapp.entity.ERole;
import finki.project.weatherapp.entity.Role;
import finki.project.weatherapp.repository.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

@Configuration
public class LoadDatabase {

    private static final Logger log = LoggerFactory.getLogger(LoadDatabase.class);

    @Bean
    CommandLineRunner initDatabase(RoleRepository roleRepository) {
        return args -> {
            Optional<Role> userRole = roleRepository.findByName(ERole.ROLE_USER);
            if(userRole.isEmpty()){
                log.info("Preloading " + roleRepository.save(new Role(ERole.ROLE_USER)));
            }

            Optional<Role> adminRole = roleRepository.findByName(ERole.ROLE_ADMIN);
            if(adminRole.isEmpty()){
                log.info("Preloading " + roleRepository.save(new Role(ERole.ROLE_ADMIN)));
            }
        };
    }
}

