import React, {useEffect, useState} from "react";
import WeatherCard from "../components/WeatherCard";
import useFetch from "../services/useFetch";
import "./Home.css";
import authenticationHeader from "../services/authenticationHeader";
import userService from "../services/userService";
import {toast} from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
toast.configure()

const Home = ({loggedUser}) => {

    const BASE_WEATHER_URL = "https://the-current-weather.herokuapp.com/api/weather/";
    const LOCATION_URL = "https://the-current-weather.herokuapp.com/api/locations/weather";

    const [weatherUrl, setWeatherUrl] = useState('https://the-current-weather.herokuapp.com/api/weather/New York, United States of America');
    const [typedLocation, setTypedLocation] = useState('New York, United States of America');
    const [savedLocationsCount, setSavedLocationsCount] = useState(0);
    const [saveLocationLoading, setSaveLocationLoading] = useState(false);

    const {data: weatherData, isLoading: weatherLoading, error: weatherError} = useFetch(weatherUrl, {});

    const {data: locationsWeather, isLoading: locationsWeatherLoading, locationsWeatherError, reFetch: reFetchLocationsWeather} = useFetch(LOCATION_URL, {
        method: 'GET',
        headers: authenticationHeader(),
    });

    useEffect(() => {
        if(locationsWeather){
            setSavedLocationsCount(locationsWeather.length);
        }
    }, [locationsWeather]);

    const getWeatherSubmit = (e) => {
        e.preventDefault();
        setWeatherUrl(BASE_WEATHER_URL + typedLocation);
        console.log('loc weather: ' + locationsWeather);
    }

    const saveLocation = () => {
        if(savedLocationsCount < 3){
            setSaveLocationLoading(true);
            let  locationName = weatherData.location.name + ' ' + weatherData.location.country;
            if(locationName){
                    userService.saveLocation(locationName)
                        .then(() => {
                            reFetchLocationsWeather();
                            setSaveLocationLoading(false);
                        })
                    setSaveLocationLoading(false);
            }
        } else {
            toast('You cannot save more than 3 locations!', {position: "top-center"});
        }
    }

    const deleteLocation = (e) => {
        let weatherId = e.target.parentNode.getAttribute('id');
        let locationName = locationsWeather[weatherId].location.name + ' ' + locationsWeather[weatherId].location.country;
        if(locationName){
                userService.deleteLocation(locationName)
                    .then(() => {
                            reFetchLocationsWeather();
                        })
        }
    }

    return(
      <div className="home">
          <div className="flex-container">
                <div className={`get-weather ${loggedUser ? "" : "center"}`}>
                    <div className={`search-bar ${loggedUser ? "" : "center"}`}>
                        <form onSubmit={getWeatherSubmit}>
                            <label>Get the current weather for a location</label>
                            <input
                                type="text"
                                value={typedLocation}
                                onChange={(e) => setTypedLocation(e.target.value)}
                                required
                            />
                        </form>
                    </div>
                    {weatherError && <div className="error"><h4>{weatherError}</h4></div>}
                    {weatherLoading && <div className="loading"><h4>Loading...</h4></div>}
                    {weatherData && !weatherError &&
                        <div>
                            <WeatherCard weatherData={weatherData}/>
                            {
                                loggedUser && !saveLocationLoading &&
                                <button
                                    className='form-input-btn'
                                    onClick={saveLocation}
                                >
                                    Save location
                                </button>
                            }
                            {
                                saveLocationLoading &&
                                    <h3 className="button-loading successful">Saving...</h3>
                            }
                        </div>
                    }
                </div>
              {loggedUser && locationsWeatherError && <div className="message"><h2 className="error">{locationsWeatherError}</h2></div>}
              {loggedUser && locationsWeatherLoading && <div className="message"><h2>Weather data loading...</h2></div>}
              {loggedUser && locationsWeather && !locationsWeatherError &&
                    <div className="locations-section">
                        <div className="locations-title">
                            <h2 className="successful">Saved locations</h2>
                        </div>
                        <div className="flex-container locations-cards">
                            {
                                locationsWeather
                                    .filter((weather, index) => index < 3)
                                    .map((weather, index) => (
                                        <div className="location-card" id={index} key={index}>
                                            <WeatherCard weatherData={weather}/>
                                            <button
                                                className='form-input-btn'
                                                onClick={deleteLocation}
                                            >
                                                Delete location
                                            </button>
                                        </div>
                                    ))
                            }
                        </div>
                    </div>

              }
          </div>
      </div>
    );
}

export default Home;