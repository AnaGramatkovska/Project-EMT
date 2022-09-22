
const validateRegister = (username, password, confirmPassword) => {

        let validationErrors = {};

        if (!username.trim()) {
            validationErrors.username = 'Username is required!';
        } else if(username.length < 3 || username.length > 25) {
            validationErrors.username = 'Username length: min=3, max=25'
        }

        if (!password) {
            validationErrors.password = 'Password is required!';
        } else if (password.length < 6 || password.length > 100) {
            validationErrors.password = 'Password length: min=6, max=100';
        }

        if(password !== confirmPassword) {
            validationErrors.confirmPassword = 'Passwords do not match!';
        }

    return validationErrors;
};

export default validateRegister;
