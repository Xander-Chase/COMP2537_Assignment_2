require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 60 * 60; //expires after 1 hour 

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */


const { connectToDatabase } = include('databaseConnection');
let userCollection;

async function init() {
    const database = await connectToDatabase();
    userCollection = database.db(mongodb_database).collection('users');
}

init();

app.use(express.static(__dirname + "/public"));

app.use(express.urlencoded({
    extended: false
}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}));

app.get('/', (req, res) => {
    let html = '';

    if (!req.session.authenticated) {
        // User is not logged in
        html += `
            <a href="/signup">Sign Up</a>
            <br>
            <a href="/login">Log In</a>
        `;
    } else {
        // User is logged in
        html += `
            <h1>Hello, ${req.session.name}</h1>
            <a href="/members">Members Area</a>
            <br>
            <a href="/logout">Log Out</a>
        `;
    }

    res.send(html);
});



app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({
        username: username
    }).project({
        username: 1,
        password: 1,
        _id: 1
    }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = [
        'ale-vs-lager.png',
        'beer_taxonomy.webp',
        'Beer_Flavor_Map.png'
    ];

    const randomImage = images[Math.floor(Math.random() * images.length)];

    var html = `
    <h1>Hello, ${req.session.name}</h1>
    <a href="/logout">Log Out</a>
    <br>
    <img src="${randomImage}" alt="Random image" />

    `;
    res.send(html);
});

app.get('/signup', (req, res) => {
    var html = `
    Sign Up
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='Name'>
    <input name='email' type='email' placeholder='Email'>
    <input name='password' type='password' placeholder='Password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({
        name,
        email,
        password
    });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        const message = validationResult.error.details[0].message;
        res.send(`<h3>${message}</h3><a href="/signup">Go back to Sign Up</a>`);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });
    console.log("Inserted user");

    // Store the user's name and username in the session
    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    // Redirect to the members area
    res.redirect('/members');
});


app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({
        email,
        password
    });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({
        email: email
    }).project({
        username: 1,
        password: 1,
        _id: 1,
        name: 1
    }).toArray();

    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login");
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        console.log("incorrect password");
        res.redirect("/login");
        return;
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    } else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    } else {
        res.send("Invalid cat id: " + cat);
    }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});