package finki.project.weatherapp.weatherclient;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Current {

    private String temperature;
    private List<String> weather_icons;
    private List<String> weather_descriptions;
    private String feelslike;
    private String is_day;

    public Current() {
    }

    public String getTemperature() {
        return temperature;
    }

    public void setTemperature(String temperature) {
        this.temperature = temperature;
    }

    public List<String> getWeather_icons() {
        return weather_icons;
    }

    public void setWeather_icons(List<String> weather_icons) {
        this.weather_icons = weather_icons;
    }

    public List<String> getWeather_descriptions() {
        return weather_descriptions;
    }

    public void setWeather_descriptions(List<String> weather_descriptions) {
        this.weather_descriptions = weather_descriptions;
    }

    public String getFeelslike() {
        return feelslike;
    }

    public void setFeelslike(String feelslike) {
        this.feelslike = feelslike;
    }

    public String getIs_day() {
        return is_day;
    }

    public void setIs_day(String is_day) {
        this.is_day = is_day;
    }

    @Override
    public String toString() {
        return "Current{" +
                "temperature='" + temperature + '\'' +
                ", weather_icons=" + weather_icons +
                ", weather_descriptions=" + weather_descriptions +
                ", feelslike='" + feelslike + '\'' +
                ", is_day='" + is_day + '\'' +
                '}';
    }
}
