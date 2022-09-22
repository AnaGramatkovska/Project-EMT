package finki.project.weatherapp.controller;

import finki.project.weatherapp.entity.AppUser;
import finki.project.weatherapp.entity.SavedLocation;
import finki.project.weatherapp.security.AppUserDetails;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import finki.project.weatherapp.repository.AppUserRepository;
import finki.project.weatherapp.weatherclient.RestWeatherClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/")
public class WeatherController {

    private RestWeatherClient restWeatherClient;

    private AppUserRepository appUserRepository;

    public WeatherController(RestWeatherClient restWeatherClient, AppUserRepository appUserRepository) {
        this.restWeatherClient = restWeatherClient;
        this.appUserRepository = appUserRepository;
    }

    @GetMapping("/")
    public String index() {
        return "Hello there! I'm running.";
    }

    @GetMapping("weather/{location}")
    public String getWeather(@PathVariable String location){
        return restWeatherClient.getWeather(location);
    }

    @GetMapping("locations/weather")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String getWeatherForSavedLocations(){
        AppUser loggedAppUser = getLoggedAppUser();
        Set<SavedLocation> savedLocations = loggedAppUser.getSavedLocations();

        List<String> savedLocationsNames = new ArrayList<>();
        savedLocations
                .forEach(location -> savedLocationsNames.add(location.getName()));

        return restWeatherClient.getWeather(savedLocationsNames);
    }

    @PostMapping("locations/{location}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String saveLocation(@PathVariable String location){
        if(!location.isBlank()){
            SavedLocation savedLocation = new SavedLocation(location);
            AppUser loggedAppUser = getLoggedAppUser();
            loggedAppUser.addSavedLocation(savedLocation);
            appUserRepository.save(loggedAppUser);
            return "Location has been saved!";
        } else{
            return "Error: Location query is empty!";
        }
    }

    @DeleteMapping("locations/{location}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String deleteLocation(@PathVariable String location){
        AppUser loggedAppUser = getLoggedAppUser();
        Set<SavedLocation> savedLocations = loggedAppUser.getSavedLocations();
        SavedLocation savedLocation = savedLocations
                .stream()
                .filter((loc -> loc.getName().equals(location)))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Error - location " + location + " not found!"));

        loggedAppUser.removeSavedLocation(savedLocation);
        appUserRepository.save(loggedAppUser);
        return "Location has been removed!";
    }

    private AppUser getLoggedAppUser(){
        AppUserDetails appUserDetails = (AppUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return appUserRepository.findByUsername(appUserDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("Error - user with username: " + appUserDetails.getUsername() + " not found!"));
    }

}
