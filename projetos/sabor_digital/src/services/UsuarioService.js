const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const UsuarioRepository = require('../repositories/UsuarioRepository');

class UsuarioService {
    async registrarUsuario(dados) {
        const { nome, email, senha, papel } = dados;

        if (!nome || !email || !senha) {
            throw { status: 400, mensagem: "Nome, e-mail e senha são obrigatórios" };
        }

        const usuarioExistente = await UsuarioRepository.findByEmail(email);
        if (usuarioExistente) {
            throw { status: 400, mensagem: "E-mail já cadastrado" };
        }

        const salt = await bcrypt.genSalt(10);
        const senhaCriptografada = await bcrypt.hash(senha, salt);

        const novoUsuarioId = await UsuarioRepository.create({
            nome: nome.trim(),
            email: email.trim().toLowerCase(),
            senha: senhaCriptografada,
            papel: papel || 'cliente'
        });

        return {
            sucesso: true,
            mensagem: "Usuário registrado com sucesso",
            id: novoUsuarioId
        };
    }

    async login(email, senha) {
        if (!email || !senha) {
            throw { status: 400, mensagem: "E-mail e senha são obrigatórios" };
        }

        const usuario = await UsuarioRepository.findByEmail(email.trim().toLowerCase());
        if (!usuario) {
            throw { status: 401, mensagem: "Credenciais inválidas" };
        }

        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        if (!senhaValida) {
            throw { status: 401, mensagem: "Credenciais inválidas" };
        }

        const secret = process.env.JWT_SECRET || 'sabor_digital_secret_key_jwt_default';
        const token = jwt.sign(
            {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                papel: usuario.papel
            },
            secret,
            { expiresIn: '8h' }
        );

        return {
            sucesso: true,
            mensagem: "Login realizado com sucesso",
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                papel: usuario.papel
            }
        };
    }
}

module.exports = new UsuarioService();
