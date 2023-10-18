const express = require('express');
const app = express();
const cors = require('cors');
const { insertarUsuario, verificarCredenciales, verificarCredencialesEmail} = require('./consultas');
const jwt = require('jsonwebtoken');
const e = require('express');
require('dotenv').config();



app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});
app.use(cors());
app.use(express.json());

// para verificar credenciales
const middlewareVerificarCredencialesForm = async (req, res, next) => {
    try {
        const { email, password, rol, lenguage } = req.body;
        if (email && password && rol && lenguage) {
            next();
        }
        else {
            res.status(401).json('Datos incompletos');
        }
    }
    catch (error) {
        console.log(error);
    }
};

//para verificar credenciales en login
const middlewareVerificarCredencialesLogin = async (req, res, next) => {
    try {
        const { email} = req.body;
        const usuario = await verificarCredencialesEmail(email);
        if (!usuario) {
            return res.status(404).json('Usuario o contraseña incorrectos');
        }
        req.usuario = usuario;
        next();
    } catch (error) {
        res.status(500).json(error.message);
    }
};


//middleware para validar token
const middlewareValidarToken = (req, res, next) => {
    try {
        const Authorization = req.header("Authorization");
        const token = Authorization.split("Bearer ")[1];
        if (!token) {
            return res.status(401).json('Sin token');
        }
        jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
            if (err) {
                return res.status(401).json('Token inválido');
            }
            req.email = decoded.email; 
            next();
        });
    } catch (error) {
        res.status(500).json(error.message);
    }
};
//rutas

app.post('/usuarios', middlewareVerificarCredencialesForm, async (req, res) => {
    try {
        const { email, password, rol, lenguage } = req.body;
        const resultado = await insertarUsuario(email, password, rol, lenguage);
        res.json(resultado);
    } catch (error) {
        res.status(500).json(error.message);
    }
});

app.post('/login', middlewareVerificarCredencialesLogin, async (req, res) => {
        const { email, password } = req.body;
        const usuario = await verificarCredenciales(email, password);
        if (!usuario) {
            return res.status(404).json('Usuario o contraseña incorrectos');
        }
        const token = jwt.sign({ email: usuario.email }, process.env.SECRET_KEY);
        res.send(token);
});

app.get('/usuarios', middlewareValidarToken, async (req, res) => {
    const  email  = req.email;
    console.log("este es el email: " +email);
    const usuario = await verificarCredencialesEmail(email); // Solo se pasa el email como argumento
    if (!usuario) {
        return res.status(404).json({ message: "Usuario no encontrado" });
    }
    const usuarioSinClave = {   
        email: usuario.email,
        rol: usuario.rol,
        lenguage: usuario.lenguage
    };
    res.json(usuarioSinClave);

});

//para manejar rutas inexistentes
app.use((req, res, next) => {
    res.status(404).json({ message: "Ruta no encontrada" });
});

//para reportar consultas a la base de datos
app.use((req, res, next) => {
    console.log(`Se hizo una consulta a la base de datos desde la ruta ${req.path}`);
    next();
});


// para manejar errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: "Error en el servidor" });
});


