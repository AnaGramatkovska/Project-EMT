import React from 'react';
import "./WeatherCard.css";

const WeatherCard = ({weatherData}) => {

    return (
        <div className="weather-card">
            <div className="daytime-img">
                <img
                    src={
                        weatherData.current.is_day === 'yes' && 'images/day.jpg'
                        || weatherData.current.is_day === 'no' && 'images/night.jpg'
                    }
                    alt="time of day image"
                />
            </div>
            <div className="weather-icon">
                <img src={weatherData.current.weather_icons} alt="weather icon"/>
            </div>
            <div className="content">
                <div className="localization">
                    <h3>{weatherData.location.name}</h3>
                </div>
                <div className="country" >
                    <h6>{weatherData.location.country}</h6>
                </div>
                <div className="description">
                    <h6>{weatherData.current.weather_descriptions}</h6>
                </div>
                <div className="temperature">
                    <h1>{weatherData.current.temperature} &deg;C</h1>
                </div>
                <div className="fellslike">
                    <h6>Feels like {weatherData.current.feelslike} &deg;C</h6>
                </div>
            </div>
        </div>
    );

};

export default WeatherCard;
