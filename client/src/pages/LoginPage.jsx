import { useState } from "react";
const LoginPage = () => {
    const [username, setUsername] = useState("")
    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")


    async function login(e) {
        e.preventDefault()
        const response = fetch("http://localhost:9000/login", {
            method: "POST",
            body: JSON.stringify({ username, password, email }),
            headers: {
                "Content-Type": "application/json",
            }
        })
        
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