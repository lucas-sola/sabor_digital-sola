const jwt = require('jsonwebtoken');

function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];

    if (!authHeader) {
        return res.status(401).json({
            sucesso: false,
            mensagem: "Token de autenticação não fornecido"
        });
    }

    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

    if (!token) {
        return res.status(401).json({
            sucesso: false,
            mensagem: "Formato de token inválido"
        });
    }

    const secret = process.env.JWT_SECRET || 'sabor_digital_secret_key_jwt_default';

    jwt.verify(token, secret, (erro, usuarioDecodificado) => {
        if (erro) {
            return res.status(403).json({
                sucesso: false,
                mensagem: "Token inválido ou expirado"
            });
        }

        req.usuario = usuarioDecodificado;
        next();
    });
}

function verificarAdmin(req, res, next) {
    if (!req.usuario || req.usuario.papel !== 'admin') {
        return res.status(403).json({
            sucesso: false,
            mensagem: "Acesso negado. Apenas administradores podem realizar esta operação."
        });
    }
    next();
}

module.exports = {
    verificarToken,
    verificarAdmin
};
