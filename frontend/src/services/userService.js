import authenticationHeader from "./authenticationHeader";

const LOCATION_URL = "https://the-current-weather.herokuapp.com/api/locations/";

const saveLocation = (location) => {

    const options = {
        method: 'POST',
        headers: authenticationHeader()
    }

     return fetch(LOCATION_URL + location, options)
         .then(response => {
         return response;
     });
}

 const deleteLocation = (location) => {

     const options = {
         method: 'DELETE',
         headers: authenticationHeader()
    }

     return fetch(LOCATION_URL+location, options)
         .then(response => {
             return response;
         })
 }

export default {
    saveLocation,
    deleteLocation
};