require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const {
    ObjectId
} = require('mongodb');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const path = require('path');

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 24 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'))

const {
    connectToDatabase
} = include('databaseConnection');
let userCollection;

async function init() {
    const database = await connectToDatabase();
    userCollection = database.db(mongodb_database).collection('users');


}

init();
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
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.get('/', (req, res) => {
    res.render("index");
});

app.get('/home', async (req, res) => {
    const usersName = req.session.name;
    let userType;

    res.render("home", {
        user: usersName,
        userType: userType
    });
});


app.get('/members', async (req, res) => {
    console.log(req.session.type);
    const usersName = req.session.name;

    const user = await userCollection.find({
        name: usersName
    }, {
        projection: {
            type: 1
        }
    }).toArray();

    res.render("members", {
        user: usersName,
        userType: user[0].type
    });
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>No user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('nosql-injection', {
            errorMessage: 'A NoSQL injection attack was detected!'
        });
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

    res.render('nosql-injection', {
        result
    });
});

app.get('/headerAuthenticated', async (req, res) => {

    const usersName = req.session.name;

    const user = await userCollection.findOne({
        name: usersName
    }, {
        projection: {
            type: 1
        }
    });


    res.render("headerAuthenticated", {
        user: usersName,
        userType: user.type
    });
});

app.get('/members', async (req, res) => {

    const usersName = req.session.name;
    const user = await userCollection.findOne({
        name: usersName
    }, {
        projection: {
            type: 1
        }
    });

    res.render("members", {
        user: usersName,
        userType: user.type
    });
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/loginSubmit', (req, res) => {
    res.render('loginSubmit');
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

    // Validate if any of the form fields are empty
    const validationResult = schema.validate({
        name,
        email,
        password
    });

    // Send message to submitUser.ejs if any field validation has failed
    if (validationResult.error != null) {
        console.log(validationResult.error);
        const message = validationResult.error.details[0].message;
        res.render("submitUser", {
            message: message
        });
        return;
    }

    // User bcrype to hash user's password
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        type: 'user'
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
        type: 1,
        password: 1,
        _id: 1,
        name: 1
    }).toArray();

    if (result.length != 1) {
        const message = "user not found";
        res.render("loginSubmit", {
            message: message
        });
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        req.session.type = result[0].type;


        res.redirect('/members');
        return;
    } else {
        const message = "incorrect password";
        res.render("loginSubmit", {
            message: message
        });
        return;
    }
});

function requireLogin(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}


app.get('/admin', requireLogin, async (req, res) => {
    const users = await userCollection.find().toArray();
    let errorMessage = '';

    if (req.session.type !== 'admin') {
        errorMessage = 'You do not have permission to access this page.';
    }

    res.render('admin', {
        users,
        errorMessage
    });
});


app.get('/admin/promote/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        // Update the user's type to 'admin' in the MongoDB database
        await userCollection.updateOne({
            _id: ObjectId(userId)
        }, {
            $set: {
                type: 'admin'
            }
        });

        res.redirect('/admin');
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/admin/demote/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        // Update the user's type to 'user' in the MongoDB database
        await userCollection.updateOne({
            _id: ObjectId(userId)
        }, {
            $set: {
                type: 'user'
            }
        });

        res.redirect('/admin');
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
        }
        res.redirect('/');
    });
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});