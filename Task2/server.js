require('dotenv').config();

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose');

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

app.listen(3000,() =>{ console.log('Running on port 3000')}) 


app.get('/users',  authenticateToken, async(req,res) =>{
    try {
        const users = await collection.findOne({ name: req.user.name });
        res.json(users);
    } catch (err) {
        res.status(500).send(err);
    }
});

app.post('/users', async (req,res) => {
    try{
        const hashedPassword = await bcrypt.hash(req.body.password , 10)
        const requestedRole = req.body.role;
        const allowedRoles = ['user', 'admin']
        if (!allowedRoles.includes(requestedRole)) return res.status(400).send('Invalid role');
        const user = new collection({ name: req.body.name, password: hashedPassword, refresh_token: null, roles: [requestedRole]  })
        await user.save() 
        res.status(201).send()
    }catch{
        res.status(500).send()
    }
    })

    function authenticateToken(req,res,next){
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]
        if (token == null ) return res.sendStatus(401)

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET,(err, user) =>{
            if (err) return res.sendStatus(403)
                req.user = user
            next()
        })

    };

app.get('/admin/users', authorizeRoles(['admin']), (req, res) => {res.json({ message: 'Welcome admin!' })});
    
app.get('/user/profile', authorizeRoles(['user']), (req, res) => {res.json({ message: 'Hello user!' })});
      
function authorizeRoles(allowedRoles) {
    return (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) return res.sendStatus(401);

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);

            if (allowedRoles.some(role => user.roles.includes(role))) {
            req.user = user;
            next();
            } else {
            res.status(403)
            }
        })
    }
}
    