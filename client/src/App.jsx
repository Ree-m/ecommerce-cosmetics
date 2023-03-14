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
  const [cartItems, setCartItems] = useState([])
  
  
    useEffect(() => {
        fetch("http://localhost:9000/cart", {
            credentials: "include"
        })
            .then(res => res.json())
            .then(data => setCartItems(data))
            .catch(error => console.error(error))
    
    }, []) // only  run once, when the component mounts
    
    
    




  // this is uplifting/lifting state up
  async function addToCart(productId, userId,quantity,name,price) {
    try {
      const response = await fetch(`http://localhost:9000/cart/add`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          productId, 
          userId ,
          quantity,
          name,
          price
          })
      });
      const item= await response.json();
      
        setCartItems(prevItem => [...prevItem, item])
      
    } catch (error) {
      console.error(error);
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
          <Route path="/cart" element={<CartPage cartItems={cartItems} setCartItems={setCartItems} />} />




        </Route>



      </Routes>
    </UserContextProvider>

  )
}

export default App
