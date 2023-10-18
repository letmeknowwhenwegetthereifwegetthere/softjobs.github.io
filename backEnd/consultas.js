const { Pool } = require('pg');
const format = require('pg-format');
require('dotenv').config();
const bcrypt = require('bcryptjs');

const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    allowExitOnIdle: true,
});

const insertarUsuario = async (email, password, rol, lenguage) => {
    try {
        let passwordHash = bcrypt.hashSync(password);
        const formatedQuery = format('INSERT INTO usuarios (email, password, rol, lenguage) VALUES (%L, %L, %L, %L) RETURNING *', email, passwordHash, rol, lenguage);
        const resultado = await pool.query(formatedQuery);
        if (resultado.rowCount === 1) {
            return "Usuario creado con exito";
        }
        else {
            return "Error al crear usuario";
        }
    }
    catch (error) {
        if (error.code === '23505') {
            return "El usuario ya existe";
        }
        else if (error.code === '23502') {
            return "Datos incompletos";
        }
        else if (error.code === '22P02') {
            return "Datos incorrectos";
        }
        else {
            console.log(error);
            return "Error al crear usuario";
        }
    }

};

const verificarCredenciales = async (email, password) => {

        const values = [email]
        const consulta = "SELECT * FROM usuarios WHERE email = $1"
        const { rows: [usuario], rowCount } = await pool.query(consulta, values)
        const { password: passwordEncriptada } = usuario
        const passwordEsCorrecta = bcrypt.compareSync(password, passwordEncriptada)
        if (!usuario || !passwordEsCorrecta) {
            return false;
          }
        else {
            return usuario;
        }
}

const verificarCredencialesEmail = async (email) => {
    const consulta = "SELECT * FROM usuarios WHERE email = $1";
    const value = [email]
    const {rows: [usuario]} = await pool.query(consulta, value);
    return usuario;
  };

module.exports = { insertarUsuario, verificarCredenciales,verificarCredencialesEmail };

