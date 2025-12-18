// @ts-check
const express = require("express")
const session = require("express-session")
const database = require("sqlite3")
const flash = require("connect-flash")
const bcrypt = require("bcrypt")
const app = express()
app.set("view engine","ejs")
app.set("views",'./templates')
app.use(express.urlencoded({extended:true}))
app.use(express.json())

app.use(session({
    secret:"password"
}))
app.use(flash())
app.use((req,res,next)=>{
    res.locals.flash = req.flash()
    res.locals.user = req.session.username
    next()
})

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
    if (req.session.username){
        req.flash("error","Already Logged in !")
        return res.redirect("/")
    }
    res.render("SignUp.ejs",{
        success,error
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
    if (req.session.username){
        req.flash("error",`Already logged in as ${req.session.username}`);
        return res.redirect("/");
    }
    res.render("login.ejs",{
        success,error
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
            return res.redirect("/");
        });



    })

})








app.get("/delete-account", (req, res) => {
    if (!req.session.username) {
        req.flash("error", "You're not logged in");
        return res.redirect("/");
    }
    res.render("delete-account");
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
        return res.redirect("/")
    })
})



app.get("/logout", (req, res) => {
    if (!req.session.username) {
        req.flash("error", "You're not logged in");
        return res.redirect("/");
    }
    res.render("logout");
});

app.post("/logout",(req,res)=>{
    req.session.destroy(err=>{
        if (err) req.flash("error",err.message);
    })
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
