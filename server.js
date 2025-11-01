const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================
// MySQL connection
// ==========================
const db = mysql.createConnection({
    host: 'localhost',   // ตามที่คุณต้องการ
    user: 'root',        
    password: '',        
    database: 'user'     
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('MySQL Connected...');
});

// ==========================
// JWT secret
// ==========================
const JWT_SECRET = 'mysecretkey';

// ==========================
// Register route
// ==========================
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

    const hashed = bcrypt.hashSync(password, 8);

    db.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashed],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'User registered successfully' });
        }
    );
});

// ==========================
// Login route
// ==========================
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.length === 0) return res.status(400).json({ error: 'User not found' });

        const user = result[0];
        const valid = bcrypt.compareSync(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Login success', token, user: { username: user.username } });
    });
});

// ==========================
// Protected route example
// ==========================
app.get('/protected', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        res.json({ user: decoded });
    });
});

// ==========================
// Start server
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
