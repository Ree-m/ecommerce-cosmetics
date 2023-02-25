import { useState } from 'react'
import reactLogo from './assets/react.svg'
import './App.css'
import { Routes, Route } from 'react-router-dom'
import Header from './Header'
import Layout from './Layout';
import HomePage from './pages/HomePage'
import LoginPage from './pages/LoginPage'
import SignupPage from './pages/SignupPage'
import AddPage from './pages/AddPage';
import { UserContextProvider } from './UserContext'


function App() {

  return (
    <UserContextProvider>
      <Routes>
        <Route path={"/"} element={<Layout />} >
          
          <Route index element={<HomePage />} />
          <Route path={"/login"} element={<LoginPage />} />
          <Route path={"/signup"} element={<SignupPage />} />
          <Route path="/add" element={<AddPage />} />

        </Route>



      </Routes>
    </UserContextProvider>

  )
}

export default App
