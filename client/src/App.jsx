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
import ProductPage from './pages/ProductPage';
import EditProductPage from './pages/EditProductPage';
import { CartProvider } from 'react-use-cart'
import CartPage from './pages/CartPage';


function App() {

  return (
    <UserContextProvider>
      <CartProvider>
        <Routes>
          <Route path={"/"} element={<Layout />} >

            <Route index element={<HomePage />} />
            <Route path={"/login"} element={<LoginPage />} />
            <Route path={"/signup"} element={<SignupPage />} />
            <Route path="/add" element={<AddPage />} />
            <Route path="/product/:id" element={<ProductPage />} />
            <Route path="/edit/:id" element={<EditProductPage />} />
            <Route path="/cart" element={<CartPage/>} />




          </Route>



        </Routes>
      </CartProvider>
    </UserContextProvider>

  )
}

export default App
