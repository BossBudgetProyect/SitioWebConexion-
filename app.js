// Librerías necesarias para el funcionamiento
const express = require('express');
const db = require('./db');
const bcrypt = require('bcrypt');
const session = require('express-session');


// Instanciamos app y creamos una constante para el puerto por si cambia
const app = express();
const port = 3000;

// Configurar EJS
app.set('view engine', 'ejs');

// Permitimos almacenar los datos para que no queden como indefinidos / Middleware para leer datos de formulario
app.use(express.urlencoded({extended:true}));
app.use(express.json());

// Creación de sesión para cada usuario:
app.use(session({
    secret: 'PruebaSxcrxtx', // Puedes cambiarla por una más segura
    resave: false,
    saveUninitialized: false
}));

// ESTE PROCESO ÚNICAMENTE SE APLICA CUANDO HAYAN MENSAJES QUE DESPUÉS REDIRECCIONEN A LA RUTA -- > SON LOS ALERTDATA RECORDAR IMPORTANTE
// Rutas públicas (no requieren autenticación)
// Ruta principal - Página de login
app.get("/", function(req, res) {
    const alertData = req.session.alertData || {};
    req.session.alertData = null; // Limpiar después de mostrar
    res.render("login", alertData);
});

// Ruta explícita para login (redirige a la principal)
app.get("/login", function(req, res) {
    res.redirect('/');
});

// Ruta para el formulario de registro
app.get("/registro", function(req, res) {
    const alertData = req.session.alertData || {};
    req.session.alertData = null;
    res.render("registro", alertData);
});
	
// Servir archivos estáticos desde 'public' (CSS, imágenes, JS frontend)
app.use(express.static('public'));

// Registro - método de registro
app.post('/registrar', async function(req, res) {
	const datos = req.body;

	let username = datos.username;
	let nombres = datos.nom;
	let apellidos = datos.apell;
	let password = datos.pass;
	let email = datos.email;
	let profesion = datos.prof;
	let nacimiento = datos.nacimiento;
	let expectativas = datos.expec;

	try {
		// Hashear la contraseña
		const hashedPassword = await bcrypt.hash(password, 10);

		// Consulta segura con placeholders
		let registrar = `
			INSERT INTO usuario 
			(NombreUsuario, Nombres, Apellidos, Contraseña, Correo, Profesion, FechaDeNacimiento, Expectativas) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

		let valores = [username, nombres, apellidos, hashedPassword, email, profesion, nacimiento, expectativas];

		db.query(registrar, valores, function(error) {
			if (error) {
				console.error("Error al registrar:", error);

				// Guardar alerta en sesión y redirigir a "/"
				req.session.alertData = {
					alert: true,
					alertTitle: "Error",
					alertMessage: "Error al registrar los datos.",
					alertIcon: "error",
					showConfirmButton: true,
					ruta: ""
				};
				return res.redirect('/'); 
			} else {
				console.log("Datos almacenados correctamente. Registro satisfactorio.");

				// Guardar alerta en sesión y redirigir a "/"
				req.session.alertData = {
					alert: true,
					alertTitle: "¡Registro exitoso!",
					alertMessage: "Por favor inicia sesión.",
					alertIcon: "success",
					showConfirmButton: true,
					ruta: ""
				};
				return res.redirect('/');
			}
		});
	} catch (err) {
		console.error("Error al procesar la solicitud:", err);

		req.session.alertData = {
			alert: true,
			alertTitle: "Error",
			alertMessage: "Ocurrió un error en el servidor.",
			alertIcon: "error",
			showConfirmButton: true,
			ruta: ""
		};
		return res.redirect('/');
	}
});


//Login - Metodo para la autenticacion
app.post('/login', async function(req, res) {
	const email = req.body.email;
	const password = req.body.pass;

	if (email && password) {
		db.query('SELECT * FROM usuario WHERE Correo = ?', [email], async (error, results) => {
			if (results.length == 0 || !(await bcrypt.compare(password, results[0].Contraseña))) {
				
				req.session.alertData = {
					alert: true,
					alertTitle: "Error",
					alertMessage: "USUARIO y/o PASSWORD incorrectas",
					alertIcon: 'error',
					showConfirmButton: true,
					ruta: ""
				};

				return res.redirect('/');
			} else {
				// Guardamos en la sesión los datos importantes
				req.session.loggedin = true;
				req.session.email = results[0].Correo;
				req.session.name = results[0].Nombres;
				req.session.rol = results[0].Rol;

				req.session.alertData = {
					alert: true,
					alertTitle: "¡LOGIN CORRECTO!",
					alertMessage: "¡Bienvenido a la aplicación!",
					alertIcon: 'success',
					showConfirmButton: true,
					ruta: ""
				};

				return res.redirect('/principal');
			}
		});
	} else {
		req.session.alertData = {
			alert: true,
			alertTitle: "Error",
			alertMessage: "Por favor, ingresa usuario y contraseña.",
			alertIcon: 'warning',
			showConfirmButton: true,
			ruta: ""
		};
		return res.redirect('/');
	}
});


// Middleware para restringir las páginas únicamente a los usuarios con cuenta creada
function isAuthenticated(req, res, next) {
    if (req.session.loggedin) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Rutas protegidas (requieren autenticación)
// Página principal - aplicar el middleware de autenticación
app.get('/principal', isAuthenticated, (req, res) => {
  const alertData = req.session.alertData || {};
  req.session.alertData = null;
  res.render('principal', {
    ...alertData,
    name: req.session.name, // Extracción de datos de base de datos
    email: req.session.email, // 👈 AGREGAR ESTA LÍNEA
    rol: req.session.rol
  });
});

// Página principal - aplicar el middleware de autenticación
app.get('/registroIngresos', isAuthenticated, (req, res) => {
    const alertData = req.session.alertData || {};
    req.session.alertData = null;
    res.render('registroIngresos', alertData);
});

// Página principal - aplicar el middleware de autenticación
app.get('/Reportes', isAuthenticated, (req, res) => {
    const alertData = req.session.alertData || {};
    req.session.alertData = null;
    res.render('Reportes', alertData);
});

// Página principal - aplicar el middleware de autenticación
app.get('/presupuesto', isAuthenticated, (req, res) => {
    const alertData = req.session.alertData || {};
    req.session.alertData = null;
    res.render('presupuesto', alertData);
});

// Página principal - aplicar el middleware de autenticación
app.get('/registroCredito', isAuthenticated, (req, res) => {
    const alertData = req.session.alertData || {};
    req.session.alertData = null;
    res.render('registroCredito', alertData);
});

// Ruta para cerrar la sesión, es necesario un botón que dirija a está ruta
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});


// Localhost:
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
