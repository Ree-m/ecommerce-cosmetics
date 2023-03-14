import { useState } from "react"
import { Navigate } from "react-router-dom"


const AddPage = () => {
    const [name, setName] = useState("")
    const [brand, setBrand] = useState("")
    const [price, setPrice] = useState("")
    const [files, setFiles] = useState("")
    const [redirect, setRedirect] = useState(false)

    async function addProduct(e) {
        e.preventDefault()
        console.log("add")
        const data = new FormData()
        data.set("name", name)
        data.set("brand", brand)
        data.set("price", price)
        data.set("file", files[0])


        const response = fetch("http://localhost:9000/add", {
            method: "POST",
            body: data,
            credentials: "include",

        })
        if ((await response).ok) {
            setRedirect(true)
        }
        console.log(await response)
    }

    if (redirect) {
        return <Navigate to={"/"} />
    }


    return (
        <div>
            <h1>Add new product</h1>

            <form onSubmit={addProduct}>
                <input type="text"
                    placeholder="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)} />

                <input type="text"
                    placeholder="brand"
                    value={brand}
                    onChange={(e) => setBrand(e.target.value)} />

                <input type="number"
                    placeholder="price"
                    value={price}
                    onChange={(e) => setPrice(e.target.value)} />


                <input type="file"

                    onChange={(e) => setFiles(e.target.files)} />

                <button className="btn">Add product</button>

            </form>

        </div>

    );
}

export default AddPage;
