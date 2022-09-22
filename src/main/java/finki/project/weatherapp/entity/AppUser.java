package finki.project.weatherapp.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import javax.validation.constraints.NotBlank;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.*;

@Entity
@Table(uniqueConstraints = {
        @UniqueConstraint(columnNames = "username")
})
public class AppUser {

    public static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

    private @Id @GeneratedValue Long id;

    @NotBlank
    @Size(max = 25)
    private String username;

    @JsonIgnore
    @NotBlank
    @Size(max = 100)
    private  String password;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable( name = "app_user_role",
                joinColumns = @JoinColumn(name = "app_user_id"),
                inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    @ManyToMany(cascade = {
            CascadeType.PERSIST,
            CascadeType.MERGE
    })
    @JoinTable(
            name = "app_user_saved_location",
            joinColumns = @JoinColumn(name = "app_user_id"),
            inverseJoinColumns = @JoinColumn(name = "saved_location_id")
    )

    @JsonManagedReference
    private final Set<SavedLocation> savedLocations = new HashSet<>();

    public AppUser() {
    }

    public AppUser(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setPassword(String password){
        this.password = password;
    }

    @PrePersist
    public void encodePassword(){
        password = PASSWORD_ENCODER.encode(password);
    }

    public String getPassword() {
        return password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Set<SavedLocation> getSavedLocations() {
        return savedLocations;
    }

    public void addSavedLocation(SavedLocation savedLocation){
        savedLocations.add(savedLocation);
        savedLocation.getAppUsers().add(this);
    }

    public void removeSavedLocation(SavedLocation savedLocation){
        savedLocations.remove(savedLocation);
        savedLocation.getAppUsers().remove(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppUser appUser = (AppUser) o;
        return Objects.equals(id, appUser.id) &&
                Objects.equals(username, appUser.username) &&
                Objects.equals(password, appUser.password) &&
                Objects.equals(roles, appUser.roles) &&
                Objects.equals(savedLocations, appUser.savedLocations);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username, password, roles, savedLocations);
    }

    @Override
    public String toString() {
        return "AppUser{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", role='" + roles + '\'' +
                '}';
    }
}
