const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');
const restricted = require('./auth/restricted-middleware');
const dbConnection = require('./database/dbConfig');

const server = express();

const sessionConfig = {
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'Keep it secret, keep it safe.',
  cookie: {
    maxAge: 1000 * 60 * 60 * 10, // in milliseconds
    secure: process.env.COOKIE_SECURE || false, // true means only send cookie over https
    httpOnly: true // true means JS has no access to the cookie, should always be true
  },
  resave: false,
  saveUninitialized: true, // GDPR compliance, should be true only once the user has accepted
  store: new KnexSessionStore({
    knex: dbConnection,
    tablename: 'knexsessions',
    sidfieldname: 'sessionid',
    createtable: true,
    clearInterval: 1000 * 60 *30
  })
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
    let { username, password } = req.body;

    const hash = bcrypt.hashSync(password, 14)

    Users.add({ username, password: hash })
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!`, id: user.id });
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/hash', (req, res) => {
  const name = req.query.name;
  const hash = bcrypt.hashSync(name, 14);
  res.send(`the hash for ${name} is ${hash}`);
});

server.get('/logout', (req, res) => {
  if(req.session) {
    req.session.destroy(error => {
      if(error){
        console.log(error)
        res.status(500).json({ message: "Unable to log out."});
      } else {
        res.status(200).json({ message: "Goodbye!" })
        }
    });
  } else {
    res.status(200).json({ message: "Already logged out" })
  }
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
