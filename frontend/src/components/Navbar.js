import { Link } from "react-router-dom";
import authenticationService from "../services/authenticationService";


const Navbar = ({loggedUser, setLoggedUser}) => {

    return(
        <nav className="navbar">
            <h1>The current weather</h1>
            <div className="links">
                {loggedUser && <Link className="hello-message"  to="/" onClick={ (event) => event.preventDefault() }><b>Hello, {loggedUser.username}!</b> </Link>}
                <Link to="/">Home</Link>
                {!loggedUser && <Link to="/login">Login</Link>}
                {!loggedUser && <Link to="/register">Register</Link>}
                {loggedUser && <Link to="/"
                               onClick={ () => {
                                    authenticationService.logout();
                                    setLoggedUser(null);
                               }}>Logout</Link>}
            </div>
        </nav>
    );
}

export default Navbar;