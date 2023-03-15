import { useState, useEffect } from 'react'
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



  // this is uplifting/lifting state up
  async function addToCart(productId, userId, quantity, name, price) {

    try {
      const response = await fetch("http://localhost:9000/cart/add", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, productId, quantity, name, price }),
      });
      const data = await response.json();
      return data.success;
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  return (
    <UserContextProvider>
      <Routes>
        <Route path={"/"} element={<Layout />} >

          <Route index element={<HomePage />} />
          <Route path={"/login"} element={<LoginPage />} />
          <Route path={"/signup"} element={<SignupPage />} />
          <Route path="/add" element={<AddPage />} />
          <Route path="/product/:id" element={<ProductPage addToCart={addToCart} />} />
          <Route path="/edit/:id" element={<EditProductPage />} />
          <Route path="/cart/:userId" element={<CartPage  />} />



        </Route>



      </Routes>
    </UserContextProvider>

  )
}

export default App
