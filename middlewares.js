const session = require ("express-session")
const flash = require("connect-flash")
const jwt = require("jsonwebtoken")
const cookie_parser = require("cookie-parser")
const express = require("express")
const crypto = require("crypto");

require("dotenv").config()

const JWT_PASSPHRASE = process.env.JWT_PASSPHRASE || "my_jwt_key"

function default_middlewares(app){
    
    app.set("views","templates")
    app.set("view engine","ejs")
    app.use(express.urlencoded({extended:true}))
    app.use(express.json())
    app.use(cookie_parser())
    
    app.use(session({
        secret: process.env.SESSION_SECRET || "password",
        resave: false,
        saveUninitialized: false
    }))
    app.use(flash())
    
    



}

function custom_middlewares(app){
    
    app.use((req,res,next)=>{
        let token = req.cookies.JWT
        if (!token) return next()
        try{
            const decoded = jwt.verify(token,JWT_PASSPHRASE)
            req.session.username = decoded.username;
        }catch(err){
            res.clearCookie("JWT")
            req.session.destroy()
            return res.render("Error.ejs",{message : err.message})
        }
        next()

    })
    app.use((req,res,next)=>{

            res.locals.flash = req.flash()
            res.locals.user = req.session.username
            next()
        })
    
}

function my_routes(app){
    const route_generator = express.Router()
    const route_verifier = express.Router()
    function generation_csrf(req,res,next){
        if (!req.session.csrf) {
            
            req.session.csrf = crypto.randomBytes(32).toString("base64");
        }
        res.locals.csrfToken = req.session.csrf;
        next()
    }
    function verification_csrf(req,res,next){
        const csrf = req.body.csrf;
        (csrf == req.session.csrf) ? next()
        : 
        res.render("Error.ejs",{message : "forged csrf"}) 
    }

    route_generator.get("/login",generation_csrf)
    route_generator.get("/logout",generation_csrf)
    route_generator.get("/signup",generation_csrf)
    route_generator.get("/delete-account",generation_csrf)

    route_verifier.post("/login",verification_csrf)
    route_verifier.post("/logout",verification_csrf)
    route_verifier.post("/signup",verification_csrf)
    route_verifier.post("/delete-account",verification_csrf)

    app.use(route_generator);
    
    app.use(route_verifier)
    

}

module.exports = {
    default_middlewares,
    custom_middlewares,
    my_routes
}
