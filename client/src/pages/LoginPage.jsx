import { useState,useContext } from "react"
import { Navigate } from "react-router-dom"
import { UserContext } from "../UserContext"

const LoginPage = () => {
    const [username, setUsername] = useState("")
    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")
    const { setUserInfo } = useContext(UserContext)
    const [redirect, setRedirect] = useState(false)




    async function login(e) {
        e.preventDefault()
        const response = fetch("http://localhost:9000/login", {
            method: "POST",
            body: JSON.stringify({ username, password, email }),
            headers: {"Content-Type": "application/json"},
            credentials:"include"
        })
        // if response is true,redirect is true
        if(response.ok){
            console.log(response)
            response.json().then(userInfo=>{
                setUserInfo(userInfo)
                setRedirect(true)

            })
        
        }else {
            alert("wrong credentials")
        }
    
        
    }

    // if redirect is true,redirect to homepage from loginpage
    if(redirect){
        return <Navigate to={"/"} />
    }
    

    return (
        <form className="login-page" onSubmit={login}>

            <h1>Login</h1>

            <input type="text"
                placeholder="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)} />

            <input type="password"
                placeholder="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)} />

            <input type="email"
                placeholder="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)} />
            <button className="btn">Login</button>
        </form>
    );
}

export default LoginPage;