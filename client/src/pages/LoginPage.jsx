import { useState } from "react";
const LoginPage = () => {
    const [username,setUsername]=useState("")
    const [password,setPassword]=useState("")

    return ( 
        <form className="login-page">

            <h1>Login</h1>

            <input type="text"
                   placeholder="username"
                   value={username}
                   onChange={(e)=>setUsername(e.target.value)} />

            <input type="password"
                   placeholder="password"
                   value={password}
                   onChange={(e)=>setPassword(e.target.value)} />

                   <button className="btn">Login</button>
        </form>
     );
}
 
export default LoginPage;