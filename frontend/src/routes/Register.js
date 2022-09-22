import "./Form.css";
import {useEffect, useState} from "react";
import authenticationService from "../services/authenticationService";
import validateRegister from "../functions/validateRegister";
import {Link} from "react-router-dom";

const Register = () => {

    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    const [validationErrors, setValidationErrors] = useState("register not started yet");

    const{register, isLoading, error: registerError, successful, message} = authenticationService.useRegister();

    useEffect(() => {

        if(Object.keys(validationErrors).length === 0){
            register(username, password)
                .then((response) => {
                });
        }
    }, [validationErrors]);


    const handleSubmit = (e) => {
        e.preventDefault();
        setValidationErrors(validateRegister(username, password, confirmPassword));
    }

    return (
        <div className="register">
            {isLoading && <h2 className="form-message">Loading...</h2>}
            {registerError && <h2 className="form-message error">{message}</h2>}
            {successful &&
                <div className="form-message successful">
                    <h2 className="successful">{message}</h2>
                    <Link to="/login">Go to login page</Link>
                </div>
            }
            {!successful &&
                <div className="form-card">
                    <form onSubmit={handleSubmit} className='form' noValidate>
                        <h2>Create your account!</h2>
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
                            {validationErrors.password && <p>{validationErrors.password}</p>}
                        </div>
                        <div className='form-inputs'>
                            <label className='form-label'>Confirm Password</label>
                            <input
                                className='form-input'
                                type='password'
                                name='password2'
                                value={confirmPassword}
                                onChange={(e => setConfirmPassword(e.target.value))}
                            />
                            {validationErrors.confirmPassword && <p>{validationErrors.confirmPassword}</p>}
                        </div>
                        <button className='form-input-btn' type='submit'>
                            Sign up
                        </button>
                    </form>
                </div>
            }

        </div>
    );
}

export default Register;
