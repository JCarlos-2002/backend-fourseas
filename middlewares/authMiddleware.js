const jwt = require('jsonwebtoken');

const verificarToken = (req, res, next) => {
    // Obtenemos el token de la cabecera (Header) de la petición
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).json({ error: 'Acceso Denegado: No enviaste un token de seguridad' });
    }

    try {
        // Limpiamos la palabra "Bearer " si Postman o React la envían por defecto
        const tokenLimpio = token.replace('Bearer ', '');
        
        // Verificamos si el token es válido usando tu frase secreta del .env
        const verificado = jwt.verify(tokenLimpio, process.env.JWT_SECRET);
        
        // Guardamos los datos del usuario (como su id y rol) para usarlos después
        req.user = verificado;
        
        // El portero da luz verde y te deja pasar a la ruta final
        next(); 
    } catch (error) {
        res.status(401).json({ error: 'Acceso Denegado: Token inválido o ha expirado' });
    }
};

module.exports = verificarToken;