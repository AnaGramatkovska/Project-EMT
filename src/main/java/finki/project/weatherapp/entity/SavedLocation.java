package finki.project.weatherapp.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
public class SavedLocation {

    private @Id @GeneratedValue Long id;

    private String name;

    @ManyToMany(mappedBy = "savedLocations")
    @JsonBackReference
    private Set<AppUser> appUsers  = new HashSet<>();

    public SavedLocation() {}

    public SavedLocation(String query) {
        this.name = query;
    }

    public Long getId() { return id; }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<AppUser> getAppUsers() {
        return appUsers;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SavedLocation savedLocation = (SavedLocation) o;
        return Objects.equals(id, savedLocation.id) && Objects.equals(name, savedLocation.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name);
    }
}
