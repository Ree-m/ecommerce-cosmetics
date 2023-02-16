import { useState } from "react";
const RegisterPage = () => {
    const [username,setUsername]=useState("")
    const [password,setPassword]=useState("")
    async function register(e){
        e.preventDefault()
        const response=fetch("http://localhost:9000/register",{
            method:"POST",
            body:JSON.stringify({username,password}),
            headers:{
                "Content-Type":"application/json",
            }
        })
        if ( (await response).ok) { //await because we need the resposne to be fullfilled
            console.log(response)
            alert("Registeration succesful.")
        } else {
            alert("Registeration failed.")
        }
    }

    return ( 
        <form className="register-page" onSubmit={register}>

            <h1>Register </h1>

            <input type="text"
                   placeholder="username"
                   value={username}
                   onChange={(e)=>setUsername(e.target.value)} />

            <input type="password"
                   placeholder="password"
                   value={password}
                   onChange={(e)=>setPassword(e.target.value)} />

                   <button className="btn">Register</button>
        </form>
     );
}
 
export default RegisterPage;