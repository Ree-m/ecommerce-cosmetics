import { useState, useEffect } from 'react';
import { useParams } from 'react-router';
import { useContext } from 'react';
import { UserContext } from '../UserContext';
import Product from '../Product';

const CartPage = ({cartItems,setCartItems}) => {

    


    const { id } = useParams()
    const { userInfo } = useContext(UserContext)

    async function removeFromCart(productId) {
        try {
            await fetch(`http://localhost:9000/cart/${userInfo.id}/${productId}`, {
                method: "DELETE",
                credentials: "include"
            })
            setCartItems(() => cartItems.filter((item) => item.productId !== productId)) //cart items with productId not equal to the deleted productid stay

        } catch (error) {
            console.error(error);

        }

    }

    async function updateQuantity(productId, quantity) {
        try {
            const response = await fetch(`http://localhost:9000/edit/${productId}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ quantity })
            })
            const updated = await response.json()
            setCartItems(items =>
                items.map(item => item.productId === productId ? updated : item)) //take the full cart,then map through it,if the item is the one being updated ,give updated else give item

        } catch (error) {
            console.error(error)
        }
    }

    const handleUpdateQuantity = (productId, quantity) => {
        updateQuantity(productId, quantity);
    }

    return (
        <>
            {cartItems.length == 0 ? ("Cart is Empty") :
                (cartItems.map((item) => (

                    <div key={item._id}>
                        <h2>{item.name}</h2>
                        <p>Price: ${item.price}</p>
                        <p>Quantity: {item.quantity}</p>

                        <br />
                        <button onClick={() => removeFromCart(item.productId)}>Delete</button>
                        <br />
                        {/* <form>
                            <span>Qunatity:</span>
                            <input type="number"
                                min="1"
                                value={item.quantity}
                                onChange={(e) => handleUpdateQuantity(item.productId, e.target.value)} />
                            <button onClick={() => handleUpdateQuantity(item.productId, item.quantity)}>Save update</button>
                        </form> */}
                    </div>
                ))
                )}

        </>
    );
}

export default CartPage;