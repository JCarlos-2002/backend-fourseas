require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const verificarToken = require('./middlewares/authMiddleware');
app.use(cors());
app.use(express.json()); 

// Conexión a la Base de Datos PostgreSQL
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

pool.connect()
    .then(() => console.log('🔥 Éxito: Conectado a la base de datos fourseas_db en PostgreSQL'))
    .catch(err => console.error('❌ Error crítico al conectar a la BD:', err));

// ==========================================
// RUTAS DE SEGURIDAD (APF2)
// ==========================================

// 1. RUTA DE REGISTRO (Encriptando la contraseña con BCrypt)
app.post('/api/registro', async (req, res) => {
    try {
        const { nombre, rol, username, password } = req.body;
        
        // Generar el Hash de la contraseña (BCrypt)
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Insertar en BD usando consultas parametrizadas ($1, $2) para evitar Inyección SQL (OWASP)
        const nuevoUsuario = await pool.query(
            'INSERT INTO usuarios (nombre, rol, username, password_hash) VALUES ($1, $2, $3, $4) RETURNING id_usuario, nombre, username, rol',
            [nombre, rol, username, passwordHash]
        );

        res.status(201).json({ mensaje: 'Usuario registrado con éxito', usuario: nuevoUsuario.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar el usuario en el servidor' });
    }
});

// 2. RUTA DE LOGIN (Generando el Token JWT)
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Buscar si el usuario existe en la BD
        const usuario = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        if (usuario.rows.length === 0) {
            return res.status(401).json({ error: 'Acceso Denegado: Usuario o contraseña incorrectos' });
        }

        // Comparar la contraseña ingresada con la contraseña encriptada en la BD
        const validPassword = await bcrypt.compare(password, usuario.rows[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Acceso Denegado: Usuario o contraseña incorrectos' });
        }

        // Generar el Token de Seguridad (JWT)
        const token = jwt.sign(
            { id: usuario.rows[0].id_usuario, rol: usuario.rows[0].rol },
            process.env.JWT_SECRET,
            { expiresIn: '2h' } // El token expira en 2 horas por seguridad
        );

        res.status(200).json({ mensaje: '¡Login exitoso!', token: token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error en el servidor durante el login' });
    }
});

// 3. GET: Ver todos los pedidos (Solo personal autenticado)
app.get('/api/pedidos', verificarToken, async (req, res) => {
    try {
        // El middleware verificarToken ya validó la identidad
        const result = await pool.query('SELECT * FROM pedidos ORDER BY id_pedido DESC');
        res.status(200).json(result.rows);
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Error al obtener los pedidos' });
    }
});

// 4. POST: Crear un nuevo pedido desde Recepción
app.post('/api/pedidos', verificarToken, async (req, res) => {
    const { total_pago, id_cliente } = req.body;
    
    try {
        // Extraemos el ID del recepcionista del Token decodificado
        const id_usuario_recepcion = req.user.id; 
        
        // Consulta parametrizada para evitar Inyección SQL (OWASP A03)
        const nuevoPedido = await pool.query(
            'INSERT INTO pedidos (total_pago, estado_pedido, id_cliente, id_usuario_recepcion) VALUES ($1, $2, $3, $4) RETURNING *',
            [total_pago, 'Pendiente', id_cliente, id_usuario_recepcion]
        );
        
        res.status(201).json({
            mensaje: 'Pedido registrado con éxito',
            pedido: nuevoPedido.rows[0]
        });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Error al registrar el pedido' });
    }
});

// Levantar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Back-End corriendo en http://localhost:${PORT}`);
});