import  { useState} from 'react';

const API_URL = "https://the-current-weather.herokuapp.com/api/authentication/";
const useLogin = () => {

    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(false);
    const [successful, setSuccessful] = useState(false);
    const [message, setMessage] = useState('');

    const login = (username, password) => {

        setIsLoading(true);
        setError(false);
        setMessage('');
        setSuccessful(false);

        return fetch(API_URL + "signin", {
            method: 'POST',
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                password: password
            })
        })
            .then(response => {
                if(!response.ok){
                    throw response;
                }
                return response.json();
        })
            .then(data => {
                if(data.accessToken){
                    localStorage.setItem("user", JSON.stringify(data));
                }
                setIsLoading(false);
                setSuccessful(true);
                setError(false);
                setMessage(data.message);
                return;
        })
            .catch(error => {
                setIsLoading(false);
                setError(true);
                setSuccessful(false);
                if(error instanceof Error){
                    setMessage(error.message);
                    console.log(error.message);
                    return;
                }
                 error.json()
                    .then(errorJson => {
                        setMessage(errorJson.message);
                        console.log(errorJson.message);
                        return;
                    })
        });
    }

    return {login, isLoading, error, successful, message}
}

const logout = () => {
    localStorage.removeItem("user");
    console.log("logged out");
};

const useRegister = () => {

    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(false);
    const [successful, setSuccessful] = useState(false);
    const [message, setMessage] = useState('');

    const register = (username, password) => {

        setIsLoading(true);
        setError(false);
        setSuccessful(false);
        setMessage('');

        return fetch(API_URL + "signup", {
            method: 'POST',
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                password: password
            })})
            .then(response => {
                if(!response.ok){
                    throw response;
                }
                return response.json();
        })
            .then(data => {
                setIsLoading(false);
                setSuccessful(true);
                setError(false);
                setMessage(data.message);
                return;
        })
            .catch(error => {
                setIsLoading(false);
                setError(true);
                setSuccessful(false);
                if(error instanceof Error){
                    setMessage(error.message);
                    return;
                }
                return error.json()
                    .then((errorJson) => {
                        setMessage(errorJson.message);
                        return;
                    })
        });

    }

    return {register, isLoading, error, successful, message}
}

const getCurrentUser = () => {
    return JSON.parse(localStorage.getItem("user"));
};

export default {
    useLogin,
    logout,
    useRegister,
    getCurrentUser,
};