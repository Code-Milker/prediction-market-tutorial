
import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
const app = express();
const port = 3000;

app.use(bodyParser.json());

interface User {
  username: string;
  password: string;
}

const users: User[] = []; // This will act as our "database" for this example

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret_key';

// Middleware to protect routes
const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.post('/register', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.status(201).send('User registered');
});

app.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = users.find(user => user.username === username);
  if (!user) return res.status(400).send('Cannot find user');

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Incorrect password');

  const accessToken = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ accessToken });
});

app.get('/protected', authenticateToken, (req: Request, res: Response) => {
  res.send('This is a protected route');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
