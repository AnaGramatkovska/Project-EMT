import Navbar from './components/Navbar';
import Home from "./routes/Home";
import {BrowserRouter, HashRouter, Route, Switch} from 'react-router-dom';
import Login from "./routes/Login";
import {useEffect, useState} from "react";
import Register from "./routes/Register";
import authenticationService from "./services/authenticationService";
import {toast} from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
toast.configure()

function App() {

    const [loggedUser, setLoggedUser] = useState(null);

    useEffect(() => {
        setLoggedUser(authenticationService.getCurrentUser());
    }, []);

  return (
    <BrowserRouter>
        <div className="App">
            <Navbar loggedUser={loggedUser} setLoggedUser={setLoggedUser}/>
            <div className="content">
                <Switch>
                    <Route exact path="/">
                        <Home loggedUser={loggedUser}/>
                    </Route>
                    <Route exact path="/login">
                        <Login setLoggedUser={setLoggedUser}/>
                    </Route>
                    <Route exact path="/register">
                        <Register/>
                    </Route>
                </Switch>
            </div>
        </div>
    </BrowserRouter>
  );

}

export default App;
