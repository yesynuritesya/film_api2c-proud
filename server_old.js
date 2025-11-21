require('dotenv').config();
const express = require('express');
const db = require('./database'); 
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const cors = require('cors'); 
const { authenticateToken, authorizeRole } = require('./middleware/auth');
const JWT_SECRET = process.env.JWT_SECRET; 
const PORT = process.env.PORT || 3300;

if (!db) {
    console.error("FATAL ERROR: Koneksi database (db) gagal dimuat atau null. Cek file database.js.");
    process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// RUTE AUTENTIKASI 1. Registrasi (/auth/register)
app.post('/auth/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
        return res.status(400).json({ error: 'Username dan password (min 6 char) harus diisi' });
    }
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) { return res.status(500).json({ error: 'Gagal memproses pendaftaran' }); }
        const sql = 'INSERT INTO users (username, password, role) VALUES (?,?,?)';
        const params = [username.toLowerCase(), hashedPassword,'user'];
        db.run(sql, params, function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint')) {
                    return res.status(409).json({ error: 'Username sudah digunakan' }); 
                }
                // Logika error db.run() memerlukan objek db yang valid
                return res.status(500).json({ error: 'Gagal menyimpan pengguna' });
            }
            res.status(201).json({ message: 'Registrasi berhasil', userId: this.lastID }); 
        });
    });
});

// END POINT HANYA UNTUK PRNGUJIAN, HAPUS DI PRODUKSI
app.post('/auth/register-admin', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username dan password wajib diisi' });

    const hashed = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`;
    const params = [username.toLowerCase(), hashed, 'admin'];

    db.run(sql, params, function (err) {
      if (err) {
        if (err.message.includes('UNIQUE'))
          return res.status(409).json({ error: 'Username admin sudah ada' });
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ message: 'Admin berhasil dibuat', userId: this.lastID });
    });
  } catch (err) {
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});


// 2. Login (/auth/login) 
app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { return res.status(400).json({ error: 'Username dan password harus diisi' }); }

    const sql = "SELECT * FROM users WHERE username = ?";
    db.get(sql, [username.toLowerCase()], (err, user) => {
        if (err || !user) { return res.status(401).json({ error: 'Kredensial tidak valid' }); }

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) { return res.status(401).json({ error: 'Kredensial tidak valid' }); }

            const payload = {
               user: { 
                id: user.id,
                username: user.username,
                role: user.role
                }
                  }; 
            jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
                if (err) { return res.status(500).json({ error: 'Gagal membuat token' }); }
                res.json({ message: 'Login berhasil', token: token }); 
            });
        });
    });
});


// movies

// GET semua film (publik)
app.get('/movies', (req, res) => {
  db.all('SELECT * FROM movies', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Tambah film (perlu token)
app.post('/movies', authenticateToken, (req, res) => {
  const { title, director, year } = req.body;
  db.run(
    'INSERT INTO movies (title, director, year) VALUES (?, ?, ?)',
    [title, director, year],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });

      console.log(`Film ditambahkan oleh user: ${req.user.username}`); // sesuai modul
      res.status(201).json({ id: this.lastID, title, director, year });
    }
  );
});

// update film (perlu admin)
app.put('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  const { title, director, year } = req.body;
  db.run(
    `UPDATE movies SET title=?, director=?, year=? WHERE id=?`,
    [title, director, year, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      console.log(`Film diperbarui oleh admin: ${req.user.username}`);
      res.json({ message: 'Film berhasil diperbarui' });
    }
  );
});


// hapus film (perlu admin)
app.delete('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
    // Perbaikan: Kueri SQL dibungkus dengan backticks
    db.run('DELETE FROM movies WHERE id=?', [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        // Perbaikan: Template literal konsol
        console.log('Film dihapus oleh admin: ${req.user.username}');
        res.json({ message: 'Film berhasil dihapus' });
});
});


// directors

// GET semua sutradara (publik)
app.get('/directors', (req, res) => {
  db.all('SELECT * FROM directors', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// tambah sutradara (perlu login)
app.post('/directors', authenticateToken, (req, res) => {
  const { name, birthYear } = req.body;
  db.run(
    'INSERT INTO directors (name, birthYear) VALUES (?, ?)',
    [name, birthYear],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      console.log('Sutradara ditambahkan oleh user: ${req.user.username}');
      res.status(201).json({ id: this.lastID, name, birthYear });
    }
  );
});



// update sutradara (perlu admin)
app.put('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  const { name, birthYear } = req.body;
  db.run(
    'UPDATE directors SET name=?, birthYear=? WHERE id=?',
    [name, birthYear, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      console.log('Sutradara diperbarui oleh admin: ${req.user.username}');
      res.json({ message: 'Data sutradara berhasil diperbarui' });
    }
  );
});



// hapus sutradara (perlu admin)
app.delete('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  db.run('DELETE FROM directors WHERE id=?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    console.log(`Sutradara dihapus oleh admin: ${req.user.username}`);
    res.json({ message: 'Data sutradara berhasil dihapus' });
  });
});




app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});