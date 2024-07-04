require('dotenv').config();

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')

const databaseUrl="mongodb+srv://achauque14:2526Chauque!@alanchauquedev.jzizany.mongodb.net/?retryWrites=true&w=majority&appName=AlanChauqueDev";
mongoose.connect(databaseUrl)
.then(()=>{
    console.log("mongodb Connected");
})
.catch(()=>{
    console.log("failed to connect");
})

const loginSchema = new mongoose.Schema({
    name:{
        type: String, 
        required:true,
        unique:true,
    },
    password:{
        type: String, 
        required:true
    },
    refresh_token:{
    type: String
    },
    roles:{
        type: [String]
    }
})

const collection = mongoose.model('UsersTest', loginSchema);

app.use(express.json())

app.listen(4000,() =>{ console.log('Running on port 4000')}) 

app.post('/token', async(req,res) =>{
    const refreshToken = req.body.token
    if(refreshToken == null) return res.sendStatus(401);
    try{
        const user = await collection.findOne({refresh_token: refreshToken});
        if (!user) return res.sendStatus(403);
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
            if(err) return res.sendStatus(403);
            const accessToken = generateAccessToken({name: decoded.name})
            res.json ({accessToken: accessToken})
    });
}catch(err){
    console.log('error in /token route', err)
    res.sendStatus(500)

}
})

app.post('/users/login', async (req,res) =>{
    const user =  await collection.findOne({ name: req.body.name })
    if (user == null){
        return res.status(400).send('cannot find user')
    }
    try{
        if(await bcrypt.compare(req.body.password, user.password)){
            const accessToken = generateAccessToken(user)
            const refreshToken = jwt.sign({id: user._id, name: user.name}, process.env.REFRESH_TOKEN_SECRET)

            user.refreshToken = refreshToken
            await collection.updateOne({name: user.name}, {refresh_token: refreshToken})
            res.json({accessToken: accessToken, refreshToken: refreshToken})
        }else{
            res.send(' Not allowed')
        }
    }catch{
        res.status(500).send()
    }
})

function generateAccessToken(user){
    return jwt.sign(
        (
            {
            id: user._id,
            name: user.name,
            roles: user.roles,
            }
        ), process.env.ACCESS_TOKEN_SECRET,
        {expiresIn: '30d'}
    )

}