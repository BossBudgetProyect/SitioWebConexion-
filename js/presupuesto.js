// Elementos del formulario
const tipoMovimiento = document.getElementById('menu1');
const categoria = document.getElementById('menu2');
const tipo = document.getElementById('menu3');
const montoInput = document.getElementById('monto');
const botonRegistrar = document.querySelector('button');

// Diccionarios de texto para construir IDs
const categoriaMap = {
  opcion1: "Casa",
  opcion2: "Comida",
  opcion3: "Trabajo",
  opcion4: "Otros"
};

const tipoMap = {
  opcion1: "Ingreso",
  opcion2: "Gasto"
};

const menu1Map = {
  opcion1: "Presupuestado",
  opcion2: "Real"
};

// Evento principal
botonRegistrar.addEventListener('click', () => {
  const tipoMov = tipoMovimiento.value;
  const cat = categoria.value;
  const tipoVal = tipo.value;
  const monto = parseFloat(montoInput.value) || 0;

  if (monto <= 0) {
    alert("Por favor, introduce un monto válido.");
    return;
  }

  const catText = categoriaMap[cat];
  const tipoText = tipoMap[tipoVal];
  const menu1Text = menu1Map[tipoMov];

  const idCelda = `${tipoText.toLowerCase()}${catText}${menu1Text}`;
  const celda = document.getElementById(idCelda);

  if (!celda) {
    alert("Error al ubicar la celda");
    return;
  }

  const valorActual = parseFloat(celda.textContent.replace('$', '')) || 0;
  const nuevoValor = valorActual + monto;
  celda.textContent = `${nuevoValor}$`;

  actualizarBalance(catText);
  montoInput.value = "";
});

// Función para actualizar el balance
function actualizarBalance(categoria) {
  // Obtenemos los valores de los ingresos y los gastos de las celdas de la tabla
  const ingresoPres = parseFloat(document.getElementById(`ingreso${categoria}Presupuestado`).textContent.replace('$', '')) || 0;
  const gastoPres = parseFloat(document.getElementById(`gasto${categoria}Presupuestado`).textContent.replace('$', '')) || 0;
  const ingresoReal = parseFloat(document.getElementById(`ingreso${categoria}Real`).textContent.replace('$', '')) || 0;
  const gastoReal = parseFloat(document.getElementById(`gasto${categoria}Real`).textContent.replace('$', '')) || 0;

  // Calculamos el balance: (Ingreso - Gasto) de Presupuestado y Real
  const balancePresupuestado = ingresoPres - gastoPres;
  const balanceReal = ingresoReal - gastoReal;
  
  // El balance final será la diferencia entre los dos balances
  const balanceFinal = balancePresupuestado - balanceReal;

  // Referencia a la celda de balance
  const celdaBalance = document.getElementById(`balance${categoria}`);

  // Mostrar el balance en la celda
  const balanceTexto = balanceFinal > 0 ? `+${balanceFinal}$` : `${balanceFinal}$`;
  celdaBalance.textContent = balanceTexto;

  // Limpiar clases de color previas
  celdaBalance.classList.remove('text-green-600', 'text-red-600', 'text-gray-600', 'font-bold');

  // Asignar el color adecuado dependiendo del gasto real respecto al presupuesto
  if (gastoReal < gastoPres) {
    // Gasto Real menor que Gasto Presupuestado -> Color verde
    celdaBalance.classList.add('text-green-600', 'font-bold');
  } else if (gastoReal > gastoPres) {
    // Gasto Real mayor que Gasto Presupuestado -> Color rojo
    celdaBalance.classList.add('text-red-600', 'font-bold');
  } else {
    // Si los gastos son iguales -> Color gris
    celdaBalance.classList.add('text-gray-600', 'font-bold');
  }
}

