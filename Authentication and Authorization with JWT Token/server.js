const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
const secret = "secre";

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());



mongoose.connect('mongodb://127.0.0.1:27017');
mongoose.connection.on('connected', () => console.log('Connected'));
mongoose.connection.on('error', () => console.log('Connection failed with - ',err));

const Product = require('./product.model');

// Sample user data for authentication
const users = [];

// Middleware to check if token is valid and extract user data
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Login route to generate access token
app.post('/login', async (req, res) => {
    // Authenticate user
    const user = req.body;
    const fuser = users.find((user) => user.email === req.body.email);
    if (!fuser) {
        return res.status(401).send('Invalid email or password');
    }

    // Check for Correct Password
    const isPasswordValid = await bcrypt.compare(user.password, fuser.password);
    if (!isPasswordValid) {
      return res.status(400).send("Invalid email or password");
    }

    // Generate JWT token
    const accessToken = jwt.sign({user}, secret, { expiresIn: '1h' });
    res.json({ accessToken });
});

// Register User
app.post('/register', async (req, res) => {
  const user = req.body;
  // console.log(user)
  if (!user.email || !user.password) {
    return res.status(400).send("Username and password are required.");
  }

  // Storing hash of password so that it can be protected
  const hash = await bcrypt.hash(user.password, 10);
  user.password = hash;
  users.push(user);
  // console.log(users);
  res.json(user); 
})

// Added Authentication to Product page
app.get('/products', authenticateToken, (req, res) => {
    Product.find().then((products) => {
      res.send(products);
    }).catch((err) => {
      res.status(500).send({
        message: err.message || 'Some error occurred while retrieving products.'
      });
    });
  });
  
app.get('/products/:id', authenticateToken, (req, res) => {
    Product.findById(req.params.id).then((product) => {
      if (!product) {
        return res.status(404).send({
          message: `Product with id ${req.params.id} not found.`
        });
      }
      res.send(product);
    }).catch((err) => {
      if (err.kind === 'ObjectId') {
        return res.status(404).send({
          message: `Product with id ${req.params.id} not found.`
        });
      }
      return res.status(500).send({
        message: `Error retrieving product with id ${req.params.id}`
      });
    });
  });

app.post('/products', authenticateToken, (req, res) => {
    const product = new Product({
      name: req.body.name,
      price: req.body.price,
      description: req.body.description
    });
  
    product.save().then((data) => {
      res.send(data);
    }).catch((err) => {
      res.status(500).send({
        message: err.message || 'Some error occurred while creating the product.'
      });
    });
  });
  
app.put('/products/:id', authenticateToken, (req, res) => {
    Product.findByIdAndUpdate(req.params.id, {
      name: req.body.name,
      price: req.body.price,
      description: req.body.description
    }, { new: true }).then((product) => {
      if (!product) {
        return res.status(404).send({
          message: `Product with id ${req.params.id} not found.`
        });
      }
      res.send(product);
    }).catch((err) => {
      if (err.kind === 'ObjectId') {
        return res.status(404).send({
          message: `Product with id ${req.params.id} not found.`
        });
      }
      return res.status(500).send({
        message: `Error updating product with id ${req.params.id}`
      });
    });
  });
  
app.delete('/products/:id', authenticateToken, (req, res) => {
    Product.findByIdAndRemove(req.params.id).then((product) => {
      if (!product) {
        return res.status(404).send({
          message: `Product with id ${req.params.id} not found.`
        });
      }
      res.send({ message: 'Product deleted successfully!' });
    }).catch((err) => {
      res.status(500).json({
        error: err,
        message: 'Error deleting product'
      });
    });
  });



app.listen(3000, () => {
console.log('Server started on port 3000');
});