import { useEffect } from "react";
import { useContext } from "react";
import { Link } from "react-router-dom";
import { UserContext } from "./UserContext";

const Header = () => {
    const { setUserInfo, userInfo } = useContext(UserContext)

    useEffect(() => {
        fetch("http://localhost:9000/profile", {
            credentials: "include",
        }).then(response => {
            response.json().then(userInfo => {
                setUserInfo(userInfo)
            })
        })
    }, [])

    // To logout the cookie needs to be invalid
    function logout() {
        fetch("http://localhost:9000/logout", {
            method: "POST",
            credentials: "include"
        })
        setUserInfo(null)
    }
    const username = userInfo?.username //if userInfo is there,give me username
    return (
        <header className="header">
            <Link to={"/"} className="logo">SkinShop</Link>
            <nav>
                {username && (
                    <>
                        <Link to="/add">Add new product</Link>
                        <a className="logout" onClick={logout}>Logout {{ username}}</a>
                    </>
                )}
                {!username && (
                    <>
                        <Link to={"/login"}>Login</Link>
                        <Link to={"/signup"}>Signup</Link>
                    </>
                )}

            </nav>
        </header>
    );
}

export default Header;