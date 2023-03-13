import { useState, useEffect } from 'react';
import { useParams } from 'react-router';
import { useContext } from 'react';
import { UserContext } from '../UserContext';

const CartPage = ({cartItems,setCartItems}) => {
   
    const {id}=useParams()
    const { userInfo } = useContext(UserContext)

   

    async function removeFromCart(productId) {
        try{
            await fetch(`http://localhost:9000/cart/${userInfo.id}/${productId}`, {
            method: "DELETE",
            credentials: "include"
        })
        setCartItems(()=> cartItems.filter((item) => item.productId !== productId)) //cart items with productId not equal to the deleted productid stay

        }catch(error){
            console.error(error);

        }
        
    }

        return (
            <>
                { cartItems.map((item) => (
                    <div key={item._id}>
                        {item.quantity} x {item.productId}{' '}
                        
                        <button onClick={()=> removeFromCart(item.productId)}>Remove</button>
                    </div>
                ))}
                
            </>
        );
    }

    export default CartPage;