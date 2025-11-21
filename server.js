const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== MIDDLEWARE SIMPLIFICADO ====================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== CONFIGURACIÓN BASE DE DATOS ====================
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root', 
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'eduperu_db'
};

// Creer conexión a la base de datos
let pool;
try {
    pool = mysql.createPool(dbConfig);
    console.log('✅ Conectado a la base de datos MySQL');
} catch (error) {
    console.error('❌ Error conectando a MySQL:', error);
    process.exit(1);
}

// ==================== RUTAS BÁSICAS DE PRUEBA ====================

// Ruta de health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: '✅ Backend EduPerú funcionando correctamente',
        timestamp: new Date().toISOString()
    });
});

// Ruta de test
app.get('/api/test', (req, res) => {
    res.json({
        success: true,
        message: '✅ Test route working',
        data: {
            server: 'Express.js',
            database: 'MySQL',
            status: 'OK'
        }
    });
});

// ==================== RUTAS DE AUTENTICACIÓN ====================

// Registro de usuario
app.post('/api/auth/register', async (req, res) => {
    console.log('📝 Intentando registro...');
    console.log('Body recibido:', req.body);
    
    try {
        // Validar que recibimos datos
        if (!req.body) {
            return res.status(400).json({
                success: false,
                message: 'No se recibieron datos'
            });
        }

        const { username, email, password, educational_level } = req.body;

        // Validar campos requeridos
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Faltan campos requeridos: username, email, password'
            });
        }

        // Verificar si el usuario ya existe
        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'El usuario o email ya está registrado'
            });
        }

        // Hash de la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar usuario
        const userId = require('crypto').randomUUID();
        await pool.execute(
            `INSERT INTO users (id, username, email, password_hash, educational_level) 
             VALUES (?, ?, ?, ?, ?)`,
            [userId, username, email, hashedPassword, educational_level || 'Universidad']
        );

        // Generar token
        const token = jwt.sign(
            { userId: userId, username: username },
            process.env.JWT_SECRET || 'eduperu_secret',
            { expiresIn: '30d' }
        );

        console.log('✅ Usuario registrado:', username);

        res.status(201).json({
            success: true,
            message: 'Usuario registrado exitosamente',
            token: token,
            user: {
                id: userId,
                username: username,
                email: email,
                educational_level: educational_level || 'Universidad'
            }
        });

    } catch (error) {
        console.error('❌ Error en registro:', error);
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
});

// Login de usuario
app.post('/api/auth/login', async (req, res) => {
    console.log('🔐 Intentando login...');
    
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Usuario y contraseña son requeridos'
            });
        }

        // Buscar usuario
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [username, username]
        );

        if (users.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Usuario o contraseña incorrectos'
            });
        }

        const user = users[0];

        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({
                success: false,
                message: 'Usuario o contraseña incorrectos'
            });
        }

        // Generar token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            process.env.JWT_SECRET || 'eduperu_secret',
            { expiresIn: '30d' }
        );

        console.log('✅ Login exitoso:', user.username);

        res.json({
            success: true,
            message: 'Login exitoso',
            token: token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                educational_level: user.educational_level
            }
        });

    } catch (error) {
        console.error('❌ Error en login:', error);
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
});

// ==================== RUTAS DE CURSOS ====================

// Obtener todos los cursos
app.get('/api/courses', async (req, res) => {
    try {
        const [courses] = await pool.execute(
            'SELECT * FROM courses WHERE is_active = TRUE'
        );
        
        res.json({
            success: true,
            data: courses,
            total: courses.length
        });

    } catch (error) {
        console.error('Error obteniendo cursos:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener los cursos'
        });
    }
});

// Obtener cursos por categoría
app.get('/api/courses/:category', async (req, res) => {
    try {
        const { category } = req.params;
        const [courses] = await pool.execute(
            'SELECT * FROM courses WHERE category = ? AND is_active = TRUE',
            [category]
        );
        
        res.json({
            success: true,
            data: courses,
            total: courses.length
        });

    } catch (error) {
        console.error('Error obteniendo cursos por categoría:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener los cursos'
        });
    }
});

// ==================== MIDDLEWARE DE AUTENTICACIÓN ====================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Token de acceso requerido' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'eduperu_secret', (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Token inválido' 
            });
        }
        req.user = user;
        next();
    });
};

// ==================== RUTAS PROTEGIDAS ====================

// Obtener perfil del usuario
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.execute(
            'SELECT id, username, email, educational_level FROM users WHERE id = ?',
            [req.user.userId]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        res.json({
            success: true,
            data: users[0]
        });

    } catch (error) {
        console.error('Error obteniendo perfil:', error);
        res.status(500).json({
            success: false,
            message: 'Error al obtener el perfil'
        });
    }
});

// ==================== MANEJO DE RUTAS NO ENCONTRADAS ====================
// ✅ SOLUCIÓN SIMPLE - Sin usar patrones problemáticos
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Ruta no encontrada: ' + req.method + ' ' + req.originalUrl,
        suggestion: 'Verifica la URL y el método HTTP'
    });
});

// ==================== INICIAR SERVIDOR ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log('='.repeat(50));
    console.log('🚀 SERVIDOR EDUPERÚ INICIADO CORRECTAMENTE');
    console.log('='.repeat(50));
    console.log(`📍 URL Local: http://localhost:${PORT}`);
    console.log(`🌐 URL Red: http://TU_IP:${PORT}`);
    console.log(`⏰ Hora: ${new Date().toLocaleString()}`);
    console.log('='.repeat(50));
    console.log('📋 RUTAS DISPONIBLES:');
    console.log('   GET  /api/health          - Estado del servidor');
    console.log('   GET  /api/test            - Ruta de prueba');
    console.log('   GET  /api/courses         - Todos los cursos');
    console.log('   GET  /api/courses/:category - Cursos por categoría');
    console.log('   POST /api/auth/register   - Registrar usuario');
    console.log('   POST /api/auth/login      - Iniciar sesión');
    console.log('   GET  /api/users/profile   - Perfil (requiere token)');
    console.log('='.repeat(50));
    console.log('💡 Para probar inmediatamente:');
    console.log('   curl http://localhost:3000/api/health');
    console.log('='.repeat(50));
});

// Manejo de errores no capturados
process.on('unhandledRejection', (err) => {
    console.error('❌ Error no manejado:', err);
    process.exit(1);
});