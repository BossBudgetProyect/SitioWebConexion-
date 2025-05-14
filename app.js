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

// Ruta de inicio con plantilla EJS
app.get("/", function(req, res){
	res.render("login"); // views/login.ejs como ruta principal
});

// Ruta de inicio con plantilla EJS
app.get("/views/login", function(req, res){
	res.render("login"); // views/login.ejs
});

// Ruta de inicio con plantilla EJS
app.get("/views/registro", function(req, res){
	res.render("registro"); // views/registro.ejs
});
	
// Servir archivos estáticos desde 'public' (CSS, imágenes, JS frontend)
app.use(express.static('public'));


// Ruta POST para registro
app.post('/registrar', async function(req, res){
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

    // Ejecutar consulta
    db.query(registrar, valores, function (error) {
      if (error) {
        console.error("Error al registrar:", error);
        return res.status(500).send("Error al registrar los datos.");
      } else {
        console.log("Datos almacenados correctamente. Registro satisfactorio.");
        return res.status(200).send("Registro exitoso.");
      }
    });

  } catch (err) {
    console.error("Error al procesar la solicitud:", err);
    return res.status(500).send("Ocurrió un error en el servidor.");
  }
});


//Login - Metodo para la autenticacion
app.post('/login', async function(req, res){
	const email = req.body.email;
	const password = req.body.pass;    
	if (email && password) {
		db.query('SELECT * FROM usuario WHERE Correo = ?', [email], async (error, results, fields)=> {
			if( results.length == 0 || !(await bcrypt.compare(password, results[0].Contraseña)) ) {    
				res.render('login', {
                        alert: true,
                        alertTitle: "Error",
                        alertMessage: "USUARIO y/o PASSWORD incorrectas",
                        alertIcon:'error',
                        showConfirmButton: true,
                        timer: false,
                        ruta: 'login'    
                    });
				
				//Mensaje simple y poco vistoso
                //res.send('Incorrect Username and/or Password!');				
			} else {
				// Guardamos en la sesión los datos importantes
                req.session.loggedin = true; // //creamos una var de session y le asignamos true si INICIO SESSION    
                req.session.email = results[0].Correo;
                req.session.name = results[0].Nombres;
                req.session.rol = results[0].Rol; // Asegúrate de tener el campo 'Rol' en tu tabla				
				res.render('login', {
					alert: true,
					alertTitle: "Conexión exitosa",
					alertMessage: "¡LOGIN CORRECTO!",
					alertIcon:'success',
					showConfirmButton: false,
					timer: 1500,
					ruta: ''
				});        			
			}			
			res.end();
		});
	} else {	
		res.send('Please enter user and Password!');
		res.end();
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

// Ruta protegida, el principar.html (en todo caso principal.ejs) solo pueden acceder las personas con cuenta creada
app.get('/principal', isAuthenticated, (req, res) => {
    res.render('principal', { name: req.session.name, rol: req.session.rol });
});

// Ruta para cerrar la sesión, es necesario un botón que dirija a está ruta
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});


// Localhost:
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
