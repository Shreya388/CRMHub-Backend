const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// Use CORS middleware before other middleware
app.use(cors({
    origin: 'http://localhost:5173' // Your frontend URL
}));
app.use(bodyParser.json());

const JWT_SECRET = 'your_secret_key';

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/crm', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
});

const User = mongoose.model('User', userSchema);

app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).send('All fields are required.');
    }

    try {
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(409).send('Username or email already exists.');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword, email });
        await user.save();

        res.status(201).send('User registered!');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error registering user');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).send('Invalid username or password');
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).send('Invalid username or password');
        }
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).send('Error logging in');
    }
});

const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token || !token.startsWith('Bearer ')) {
        return res.status(401).send('Access denied');
    }
    const cleanToken = token.replace('Bearer ', '');

    try {
        const verified = jwt.verify(cleanToken, JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).send('Invalid token');
    }
};

app.get('/protected', authenticateJWT, (req, res) => {
    res.send(`Hello, ${req.user.username}. This is a protected route.`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
