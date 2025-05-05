
require("./utils.js");
require('dotenv').config();


const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/public"));

// db secret info
const expireTime = 1000 * 60 * 60;    // 1000 ms/s * 60 s/min * 60 min/hr
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;
var database = new MongoClient(atlasURI);
const userCollection = database.db(mongodb_database).collection('users');
var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false, 
  resave: true
}));


app.get('/', (req, res) => {
  if (!req.session.authenticated) {
    res.send(
      `<a href="/signup"><button>Sign up</button></a><br/>` + 
      `<a href="/login"><button>Log in</button></a>`
    );
  }
  else {
    res.redirect(`/members`);
  };
});

app.get('/signup', (req, res) => {
  res.send(
    `<p>Create a new user</p>` +
    `<form method="post" action="/signupSubmit">` +
    `<input type="text" placeholder="name" name="name" required/><br/>` +
    `<input type="email" placeholder="email" name="email" required/><br/>` +
    `<input type="password" placeholder="password" name="password" required/><br/>` +
    `<input type="submit" value="Submit"/>` +
    `</form>`
  );
});

app.post('/signupSubmit', async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var pw = req.body.password;   

  const schema = Joi.object({
    name:   Joi.string().alphanum().max(20).required(),
    email:  Joi.string().email({minDomainSegments: 2, tlds: { allow: ['com', 'org', 'net']}}).required(),
    pw:     Joi.string().max(20).required()
  });

  const validationResult = schema.validate({name, email, pw});

  if (validationResult.error != null) {
    if (!name) {
      res.send(
        `<p>Name is required.</p><br/><a href="/signup">Try again</a>`
      );
    }
    else if (!email) {
      res.send(
        `<p>Email is required.</p><br/><a href="/signup">Try again</a>`
      );
    }
    else if (!pw) {
      res.send(
        `<p>Password is required.</p><br/><a href="/signup">Try again</a>`
      );
    }
  }

  var hashedPw = await bcrypt.hash(pw, saltRounds);
  await userCollection.insertOne({username: name, email: email, password: hashedPw});

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
  return;
});

app.get('/login', (req, res) => {
  res.send(
    `<p>log in</p>` + 
    `<form method="post" action="/loginSubmit">` +
    `<input type="text" placeholder="email" name="email" required/><br/>` +
    `<input type="password" placeholder="password" name="password" required/><br/>` +
    `<input type="submit" value="Login"/>` +
    `</form>`
  );
});

app.post('/loginSubmit', async (req, res) => {
  var email = req.body.email;
  var pw = req.body.password;

  const schema = Joi.object({
    email:  Joi.string().email({minDomainSegments: 2, tlds: { allow: ['com', 'org', 'net']}}).required(),
    pw:     Joi.string().max(20).required()
  });
  const validationResult = schema.validate({email, pw});
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection.find({email: email}).project({username: 1, password: 1, _id: 1}).toArray();

	if (result.length != 1) {
		res.send(
      `<p>That email was not found.</p>` +
      `<a href="/login">Try again</a>`
    );
	}
	if (await bcrypt.compare(pw, result[0].password)) {
		req.session.authenticated = true;
		req.session.name = result[0].username;
		req.session.cookie.maxAge = expireTime;
		res.redirect('/members');
		return;
	}
	else {
		res.send(
      `<p>That password is incorrect.</p>` +
      `<a href="/login">Try again</a>`
    );
	}
});

app.get('/members', (req, res) => {
  if (req.session.authenticated) {
    var rnd = Math.floor(Math.random() * 3) + 1;
    var html =
      `<h1>Hello, ${req.session.name}!</h1><br/><br/>` +
      `<img src="/${rnd.toString()}.jpg"><br/>` +
      `<a href="/logout"><button>Sign out</button></a>`

    res.send(html);
  }
  else {
    res.redirect(`/`);
    return;
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect(`/`);
  return;
});

app.get('*dummy', (req, res) => {
  res.status(404);
  res.send(`Page not found - 404`
    + `<a href="/">Return to home</a>`);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});