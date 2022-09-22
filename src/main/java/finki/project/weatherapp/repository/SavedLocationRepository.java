package finki.project.weatherapp.repository;

import finki.project.weatherapp.entity.SavedLocation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SavedLocationRepository extends JpaRepository<SavedLocation, Long> {

    Optional<SavedLocation> findByName(String name);

}
