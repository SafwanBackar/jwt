require('dotenv').config()
require('./config/database').connect()
const express = require('express')
const app = express()
const User = require('./model/user')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');




app.use(express.json())


app.post('/register', async (req,res) =>{
    try{
        
        const { first_name, last_name, email, password} = req.body;
        
        if(!(email && password && first_name && last_name)){
            res.status(400).send('All input is required')
          }
    
        const oldUser = await User.findOne({email});
    
        if(oldUser){
            return res.status(409).send('User already exist. Please login')
        }
    
        encryptedPassword = await bcrypt.hash(password, 10)
        
        const user = await User.create({
            first_name,
            last_name,
            email: email.toLowerCase(),
            password: encryptedPassword,
          });
    
          const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            {
              expiresIn: "2h",
            }
          );

          res.status(201).json(user);
        } catch (err) {
          console.log(err);
        }
})

app.post('/login', async (req,res) =>{
    try {
        const { email, password } = req.body;
    
        if (!(email && password)) {
          res.status(400).send("All input is required");
        }

        const user = await User.findOne({ email });
    
        if (user && (await bcrypt.compare(password, user.password))) {
           console.log('logged in');
            
          // Create token
          const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            {
              expiresIn: "2h",
            }
          );
    
          // save user token
          user.token = token;
          console.log(user)

    
          res.json(user);
        }
        // res.status(400).send("Invalid Credentials");
      } catch (err) {
        console.log(err);
      }
})


app.post('/isauth', (req,res) =>{
    
   const token = req.headers["x-access-token"]

   if(token){
    jwt.verify(token,'mySecretKey', (err, decoded) =>{
        if(err){
           return console.log(err);
        }else{
            console.log('Verification Success');
        }
    })
  }
    
})

// verifyUser = () =>{

// }

module.exports = app;