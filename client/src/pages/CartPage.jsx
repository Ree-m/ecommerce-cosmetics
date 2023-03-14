import { useState, useEffect } from 'react';
import { useParams } from 'react-router';
import { useContext } from 'react';
import { UserContext } from '../UserContext';
import Product from '../Product';

const CartPage = () => {

    const [cartItems, setCartItems] = useState([])



    const { id } = useParams()
    const { userInfo } = useContext(UserContext)

    useEffect(() => {
        async function fetchCart() {
            try {
                const response = await fetch(`http://localhost:9000/cart/${userInfo.id}`);
                const data = await response.json();
                setCartItems(data);
            } catch (error) {
                console.error(error);
            }
        }

        fetchCart();
    }, [userInfo.id]);

console.log("this is cartItems",cartItems)
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

    // async function updateQuantity(productId, quantity) {
    //     try {
    //         const response = await fetch(`http://localhost:9000/edit/${productId}`, {
    //             method: "PUT",
    //             headers: { "Content-Type": "application/json" },
    //             body: JSON.stringify({ quantity })
    //         })
    //         const updated = await response.json()
    //         setCartItems(items =>
    //             items.map(item => item.productId === productId ? updated : item)) //take the full cart,then map through it,if the item is the one being updated ,give updated else give item

    //     } catch (error) {
    //         console.error(error)
    //     }
    // }

    // const handleUpdateQuantity = (productId, quantity) => {
    //     updateQuantity(productId, quantity);
    // }

    return (
        <>
            <h2>My Cart</h2>
            <ul>
                {cartItems.products.map((product) => (
                    <li key={product.productId}>
                        <p>{product.name}</p>
                        <p>Quantity: {product.quantity}</p>
                        <p>Price: ${product.price}</p>
                        <button onClick={removeFromCart}></button>
                    </li>
                ))}
            </ul>
        
        </>
    );
}

export default CartPage;