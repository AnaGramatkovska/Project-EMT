import React from 'react';

const validateLogin = (username, password) => {

    let validationErrors = {};

    if (!username.trim()) {
        validationErrors.username = 'Username is required!';
    }

    if (!password) {
        validationErrors.password = 'Password is required!';
    }

    return validationErrors;
};

export default validateLogin;
