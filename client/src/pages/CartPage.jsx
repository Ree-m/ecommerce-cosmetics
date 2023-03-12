const CartPage = ({ cart,setCart }) => {
    
    function handleRemove(id){
        const filtered = cart.filter((product) => product._id !== id);
        setCart(filtered)


    }
    return (
        <>
            {cart && cart.map((product) => (
                <div className="product-title">
                    <p>{product.name}</p>
                    <span>{product.price}</span>
                    <button onClick={() => handleRemove(product._id)}>Remove</button>
                </div>
            ))}
        </>
    );
}

export default CartPage;