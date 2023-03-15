import { useState, useEffect } from 'react';
import { useParams } from 'react-router';
import { useContext } from 'react';
import { UserContext } from '../UserContext';
import Product from '../Product';

const CartPage = () => {

    const { userInfo } = useContext(UserContext)
    const [cartItems, setCartItems] = useState(null)




    // useEffect(() => {
    //     const userId = userInfo.id
    //     console.log(userId); // log the userId to the console
    //     fetch(`http://localhost:9000/cart/${userInfo._id}`, {
    //       credentials: "include"
    //     })
    //       .then(res => res.json())
    //       .then(data =>
    //         setCartItems(data)
    //         )
    //         console.log('this is data',data) 

    //       .catch(error => console.error(error))
    // },[]) // only  run once, when the component mounts

    useEffect(() => {
        fetch(`http://localhost:9000/cart/${userInfo.id}`, {
            credentials: "include",
        })
            .then((res) => res.json())
            .then((data) => {
                console.log("this is data", data); // check the response from the server
                setCartItems(data);
            })
            .catch((error) => console.error(error));
    }, [userInfo.id]);


if(cartItems){
    console.log("this is cartItems", cartItems[0].products.map((item=>item.name)))

}

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
            <h2>Cart</h2>
            {cartItems &&cartItems[0].products.map((item) => (
                <div key={item._id}>
                    <p>{item.name}</p>
                    <p>Quantity: {item.quantity}</p>
                    <p>Price: ${item.price}</p>
                    
                </div>
            ))}

        </>
    );
}

export default CartPage;