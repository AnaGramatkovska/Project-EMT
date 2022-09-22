package finki.project.weatherapp.weatherclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

@Service
public class RestWeatherClient {

    @Value("${api.url}")
    private String API_URL;

    private RestTemplate restTemplate;

    private ObjectMapper objectMapper;

    public RestWeatherClient(RestTemplateBuilder restTemplateBuilder) {
         restTemplate = restTemplateBuilder.build();
         this.objectMapper = new ObjectMapper();
    }

    public String getWeather(String locationQuery)  {
        Weather weather = restTemplate
                .getForObject(API_URL+locationQuery, Weather.class);

        String weatherJson = null;
        try {
            weatherJson = objectMapper.writeValueAsString(weather);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return  weatherJson;
    }

    public String getWeather(List<String> locations){
        List<Weather> locationsWeather = new ArrayList<>();
        locations
                .forEach( (location) -> locationsWeather.add(restTemplate.getForObject(API_URL + location, Weather.class)));
        String locationsWeatherJson = null;
        try{
            locationsWeatherJson = objectMapper.writeValueAsString(locationsWeather);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return locationsWeatherJson;
    }

}
