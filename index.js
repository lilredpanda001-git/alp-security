const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const SECRET_KEY = 'kunci_rahasia_alp_2024'; // Kunci rahasia untuk JWT

// Data Dummy Pengguna
const users = [
    { id: 1, username: 'admin', password: '123', role: 'Admin', department: 'IT' },
    { id: 2, username: 'budi', password: '123', role: 'Manager', department: 'HR' },
    { id: 3, username: 'siti', password: '123', role: 'Staff', department: 'HR' }
];

// Data Dummy Dokumen
let documents = [
    { id: 101, title: 'Laporan Gaji.pdf', ownerId: 2, department: 'HR' },
    { id: 102, title: 'Draft Cuti Siti.pdf', ownerId: 3, department: 'HR' }
];

// Jalankan Server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));

// --- #1 ACCESS TOKEN (Login) ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);

    if (user) {
        // Buat payload token berisi ID, Role, dan Atribut (Department)
        const token = jwt.sign({ id: user.id, role: user.role, department: user.department }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ message: 'Login berhasil', token });
    } else {
        res.status(401).json({ message: 'Username atau password salah' });
    }
});

// Middleware untuk memverifikasi JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user; // Simpan data user ke request
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// Middleware RBAC
const authorizeRole = (role) => {
    return (req, res, next) => {
        if (req.user.role === role) {
            next(); // Lolos
        } else {
            res.status(403).json({ message: 'Akses ditolak: Membutuhkan role ' + role });
        }
    };
};

// --- #2 RBAC Endpoint ---
// Hanya Admin yang bisa melihat daftar semua user
app.get('/api/users', authenticateJWT, authorizeRole('Admin'), (req, res) => {
    res.json(users);
});

// --- #3 ABAC Endpoint ---
// Staff hanya bisa mengakses dokumen miliknya sendiri (ownerId == req.user.id)
app.get('/api/documents/:id', authenticateJWT, (req, res) => {
    const docId = parseInt(req.params.id);
    const document = documents.find(d => d.id === docId);

    if (!document) return res.status(404).json({ message: 'Dokumen tidak ditemukan' });

    // Pengecekan ABAC: Apakah ID pemilik dokumen = ID pengguna yang login?
    if (document.ownerId === req.user.id || req.user.role === 'Admin') {
        res.json(document);
    } else {
        res.status(403).json({ message: 'Akses ditolak: Ini bukan dokumen Anda' });
    }
});

// --- #4 GABUNGAN RBAC & ABAC Endpoint ---
app.delete('/api/documents/:id', authenticateJWT, (req, res) => {
    const docId = parseInt(req.params.id);
    const documentIndex = documents.findIndex(d => d.id === docId);

    if (documentIndex === -1) return res.status(404).json({ message: 'Dokumen tidak ditemukan' });
    const document = documents[documentIndex];

    // Pengecekan RBAC: Harus Manager
    const isManager = req.user.role === 'Manager';
    // Pengecekan ABAC: Departemen harus sama
    const isSameDepartment = document.department === req.user.department;

    if (isManager && isSameDepartment) {
        documents.splice(documentIndex, 1);
        res.json({ message: 'Dokumen berhasil dihapus' });
    } else {
        res.status(403).json({ message: 'Akses ditolak: Anda bukan Manager di departemen ini' });
    }
});