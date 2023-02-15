import { Link } from "react-router-dom";
const Header = () => {
    return (
        <header className="header">
            <nav>
                <Link to={"/login"}>Login</Link>
                <Link to={"/register"}>Register</Link>
            </nav>
        </header>
    );
}

export default Header;