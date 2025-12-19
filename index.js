// @ts-check
const express = require("express")
const database = require("sqlite3")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const app = express()

require("dotenv").config()

const {default_middlewares,custom_middlewares,my_routes} = require("./middlewares.js");

default_middlewares(app);
custom_middlewares(app);
my_routes(app);

const jwt_key = process.env.SECRET_KEY || "my_jwt_key"

const db = new database.Database('./users.db')

db.run(`create table if not exists users( 
    id integer primary key autoincrement not null, 
    username varchar(100), password varchar(100), 
    role varchar(20) default 'user' );`);

app.get("/", (req, res) => {
    let success = res.locals.flash.success;
    let error = res.locals.flash.error;
    res.render("home.ejs", {
        user: res.locals.user,
        success,
        error
    })
})

app.get("/signup",(req,res)=>{
    let success = res.locals.flash.success;
    let error = res.locals.flash.error;
    let csrf = res.locals.csrfToken;
    if (req.session.username){
        req.flash("error","Already Logged in !")
        return res.redirect("/")
    }
    res.render("SignUp.ejs",{
        success,error,csrf
    })
    
})
app.post("/signup", async (req, res) => {
    if (res.locals.user) {
        req.flash("error", "Already logged in!");
        return res.redirect("/");
    }

    let { username, password } = req.body;

    if (!username || !password) {
        req.flash("error", "Must provide username AND password!");
        return res.redirect("/signup");
    }

    try {
        let hashed_password = await bcrypt.hash(password, 10);

        db.run(
            'insert into users(username, password) values (?, ?);',
            [username, hashed_password],
            function(err) {
                if (err) {
                    req.flash("error", "Username already exists!");
                    return res.redirect("/signup");
                }
                req.session.username = username;
                let token = jwt.sign({
                username:username,
                role : "user"
            },
            jwt_key,
            {algorithm:"HS256",expiresIn : "1h"}
        )
        res.cookie("JWT",token)
                req.flash("success", `User ${username} successfully added!`);
                return res.redirect("/");
            }
        );
    } catch (e) {
        req.flash("error", "Unexpected error during signup!");
        return res.redirect("/signup");
    }
});



app.get("/login",(req,res)=>{
    let success = res.locals.flash.success;
    let error = res.locals.flash.error;
    let csrf = res.locals.csrfToken;
    if (req.session.username){
        req.flash("error",`Already logged in as ${req.session.username}`);
        return res.redirect("/");
    }
    res.render("login.ejs",{
        success,error,csrf
    })
})











app.post("/login",(req,res)=>{
    let {username,password} = req.body;
    if (!username || ! password) {
        req.flash("error","Must provide credentials");
        return res.redirect("/login")
    }
    db.get("select * from users where username = ?",[username],async (err,row)=>{
        if (err || !row){
            req.flash("error",err ? err.message : "User doesn't exist")
            return res.redirect("/login")
        }
        bcrypt.compare(password, row.password, (err, result) => {
            if (err) {
                req.flash("error", "Unexpected error");
                return res.redirect("/login");
            }

            if (!result) {
                req.flash("error", "Incorrect password");
                return res.redirect("/login");
            }

            req.session.username = username;
            req.flash("success", "Logged in successfully!");
            let token = jwt.sign({
                username:row.username,
                role : row.role
            },
            jwt_key,
            {algorithm:"HS256",expiresIn : "1h"}
        )
            res.cookie("JWT",token)
            return res.redirect("/");
        });



    })

})








app.get("/delete-account", (req, res) => {
    if (!req.session.username) {
        req.flash("error", "You're not logged in");
        return res.redirect("/");
    }
    let csrf = res.locals.csrfToken;
    
    res.render("delete",{csrf});
});

app.post("/delete-account",(req,res)=>{
    db.run("delete from users where username = ?",[req.session.username],err=>{
        if (err) {
            req.flash (`Unexpected Error Occured ${err.message}`);
            return res.redirect("/delete-account");
        }
        req.flash("success","Successfully Deleted Account");
        req.session.destroy(err => {
            if (err) req.flash("error",err.message)
        })
        res.clearCookie("JWT");
        return res.redirect("/")
    })
})



app.get("/logout", (req, res) => {
    if (!req.session.username) {
        req.flash("error", "You're not logged in");
        return res.redirect("/");
    }
    let csrf = res.locals.csrfToken;
    res.render("logout",{csrf});
});

app.post("/logout",(req,res)=>{
    req.session.destroy(err=>{
        if (err) req.flash("error",err.message);
    })
    res.clearCookie("JWT")
    return res.redirect("/")
})

app.get("/profile",(req,res)=>{
    let success = res.locals.flash.success;
    let error = res.locals.flash.error;
    let user = res.locals.user;
    if (!user){
        req.flash("error","Not even logged in");
        return res.redirect("/")
    }
    res.render("profile.ejs",{
        user,error,success})
})




app.listen(3000,()=>{
    console.log("Runnning on port 3000")
})
