import React, {useEffect, useState} from 'react';
import {useHistory} from "react-router-dom";
import "./Form.css";
import authenticationService from "../services/authenticationService";
import validateLogin from "../functions/validateLogin";

const Login = ({setLoggedUser}) => {

    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    const [validationErrors, setValidationErrors] = useState("login not started yet");

    const{login, isLoading, error: loginError, successful, message} = authenticationService.useLogin();

    const history = useHistory();

    useEffect(() => {

        if(Object.keys(validationErrors).length === 0){
            login(username, password)
                .then((response) => {
                });
        }
    }, [validationErrors]);

    useEffect(() => {
        if(successful){
            setLoggedUser(authenticationService.getCurrentUser());
            history.push("/");
        }
    }, [successful])


    const handleSubmit = (e) => {
        e.preventDefault();
        setValidationErrors(validateLogin(username, password));
    }
    return(
        <div className="login">
            {isLoading && <h2 className="form-message">Loading...</h2>}
            {loginError && <h2 className="form-message error">{message}</h2>}
            <div className="form-card">
                <form onSubmit={handleSubmit} className='form' noValidate>
                    <h1>Login</h1>
                    <div className='form-inputs'>
                        <label className='form-label'>Username</label>
                        <input
                            className='form-input'
                            type='text'
                            name='username'
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                        />
                        {validationErrors.username && <p>{validationErrors.username}</p>}
                    </div>
                    <div className='form-inputs'>
                        <label className='form-label'>Password</label>
                        <input
                            className='form-input'
                            type='password'
                            name='password'
                            value={password}
                            onChange={(e => setPassword(e.target.value))}
                        />
                        {validationErrors.username && <p>{validationErrors.username}</p>}
                    </div>
                    <button className='form-input-btn' type='submit'>
                        Sign in
                    </button>
                </form>
            </div>
        </div>
    );

}

export default Login;

