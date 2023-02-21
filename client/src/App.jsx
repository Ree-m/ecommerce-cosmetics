import { useState } from 'react'
import reactLogo from './assets/react.svg'
import './App.css'
import { Routes, Route } from 'react-router-dom'
import Header from './Header'
import Layout from './Layout';
import HomePage from './pages/HomePage'
import LoginPage from './pages/LoginPage'
import SignupPage from './pages/SignupPage'

function App() {

  return (
    <Routes>
      <Route path={"/"} element={<Layout />} >
        <Route index element={<HomePage />} />
        <Route path={"/login"} element={<LoginPage />} />
        <Route path={"/signup"} element={<SignupPage />} />


      </Route>



    </Routes>
  )
}

export default App
