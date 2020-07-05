let express = require('express');
let passport = require('passport');
let LocalStrategy = require('passport-local').Strategy;
const path = require('path');
const mongoose = require('mongoose');
const Passports = require('./database');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const crypto = require('crypto');
let app = express();
require('dotenv').config();
//database
const DB_STRING = process.env.DB_STRING;
mongoose.connect(DB_STRING,{useNewUrlParser: true,useUnifiedTopology: true});

const db = mongoose.connection;
db.once('open',()=>console.log('Connected to DB'));

//session
const store = new MongoStore({mongooseConnection: mongoose.connection, touchAfter: 24*3600,collection: 'sessions'});
app.use(session({
    secret: 'thisIsJusTaDemo',
    store: store,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // Equals 1 day (1 day * 24 hr/1 day * 60 min/1 hr * 60 sec/1 min * 1000 ms / 1 sec)
    }
}))


//middlewares
app.use(passport.initialize());
// app.use(passport.session())
app.use(express.json());
app.use(express.urlencoded({extended: true}))
app.use(express.static(path.join(__dirname+'./public')));


passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    Passports.findById(id, function(err, user) {
      done(err, user);
    });
  });


/***************** */
function validPassword(password, hash, salt) {
    let hashVerify = crypto.pbkdf2Sync(password,salt,10000,64,'sha512').toString('hex');
    return hash === hashVerify;
}
function genPassword(password) {
    let salt = crypto.randomBytes(32).toString('hex');
    let genHash = crypto.pbkdf2Sync(password,salt,10000,64,'sha512').toString('hex');

    return{
        salt: salt,
        hash: genHash
    }
}


//passport middleware
passport.use(new LocalStrategy(
    function(username,password,done){
        Passports.findOne({username: username},function(err,user){
            if(err) { return done(err) }
            if(!user){
                console.log('incorrect username')
                return done(null,false);
            }
            const verifiedPassword = validPassword(password,user.hash,user.salt);
            if(!verifiedPassword){
                console.log('Incorrect password')
                return done(null,false)
            }
            return done(null,user);
        })
    }
))

/************************ */
app.get('/',(req,res,next)=>{

    res.sendFile('index.html',{root: path.join(__dirname+'/public')});
});
app.get('/login',(req,res)=>{
    res.sendFile('login.html',{root: path.join(__dirname+'/public')});

})
app.post('/register',(req,res)=>{
    console.log(req.body);
    const saltHash = genPassword(req.body.password);
    const salt = saltHash.salt;
    const hash = saltHash.hash;

    const userinfo = new Passports({
        username: req.body.username,
        hash: hash,
        salt: salt
    })  
    userinfo.save(()=> console.log('Saved User Info'));

    res.redirect('/login');
})
app.post('/login',passport.authenticate('local',{successRedirect: '/success',failureRedirect: '/failed',failureFlash: true}));
app.listen(3000,()=>console.log('server started successfully'));