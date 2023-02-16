const User =require('../models/User')

exports.postRegister= async(req,res)=>{
    const { username, password } = req.body

    const userInfo = new User({
        username: username,
        password: password
    })
    try {
        const userInfoToSave = await userInfo.save()
        res.status(200).json(userInfoToSave)
    } catch (error) {
        console.log(error)
        res.status(400).json({ message:error })
    }
}