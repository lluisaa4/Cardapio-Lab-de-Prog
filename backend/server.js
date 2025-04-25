const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('./db');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashed]);
  res.send({ success: true });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  if (!user) return res.status(401).send({ error: 'Usuário não encontrado' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).send({ error: 'Senha incorreta' });

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.send({ token });
});

app.listen(process.env.PORT, () => {
  console.log(`Servidor rodando na porta ${process.env.PORT}`);
});
