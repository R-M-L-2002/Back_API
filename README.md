Clonar el proyecto
git clone https://github.com/R-M-L-2002/EFI_2_LopezRebeca_cA.git

Crear el entorno virtual
python3 -m venv env

Activar el entorno virtual
source env/bin/activate

Instalar requerimientos
pip install -r requirements.txt

Correr el proyecto
flask run --reload

-----------------------------------------------------------------------------------------------------------------------------------

# Endpoints API Documentacion

A continuación se describen los principales endpoints de la API 

## Autenticación y Registro

### Iniciar sesión

- **Método:** POST  
- **Endpoint:** `/login`

**Descripción:**  
Inicia sesión del usuario verificando las credenciales proporcionadas. Si las credenciales son correctas, establece la sesión.

**Ejemplo de cuerpo de solicitud:**
```html
{
    "username": "usuario123",
    "password": "contraseña"
}
```
### Registro de usuario

- **Método:** POST  
- **Endpoint:** `/register`

**Descripción:**  
Registra un nuevo usuario con un nombre de usuario y contraseña hasheada.

**Ejemplo de cuerpo de solicitud:**
```html
{
    "username": "nuevo_usuario",
    "password": "contraseña_segura"
}
```
### Gestion de Usuarios

- **Método:** POST  
- **Endpoint:** `/usuario`

**Descripción:**  
Lista todos los usuarios registrados. Solo accesible para administradores.

**Ejemplo de cuerpo de solicitud:**
```html
[
    {
        "id": 1,
        "username": "usuario123",
        "is_admin": true
    },
    {
        "id": 2,
        "username": "usuario456",
        "is_admin": false
    }
    // Otros usuarios
]

```
### Crear un nuevo usuario (Admin)

- **Método:** POST  
- **Endpoint:** `/admin`

**Descripción:**  
Crea un nuevo usuario. Solo accesible para administradores.

**Ejemplo de cuerpo de solicitud:**
```html
[
{
    "username": "usuario_admin",
    "password": "contraseña_admin"
}

]

```
## Accesorios

### Listar todos los accesorios

- **Método:** GET  
- **Endpoint:** `/accesorios`

**Descripción:**  
Lista todos los accesorios disponibles.

**Ejemplo de respuesta:**

```html
[
    {
        "id": 1,
        "tipo": "Cargador",
        "modelo_id": 3
    },
    {
        "id": 2,
        "tipo": "Audífonos",
        "modelo_id": 2
    }
    // Otros objetos de accesorio
]
```
### Crear un nuevo accesorio

- **Método:** GET,POST  
- **Endpoint:** `/accesorio/nuevo`

**Descripción:**  
Crea un nuevo accesorio. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
  "tipo": "Tipo del accesorio",
  "modelo_id": "ID del modelo asociado"
}
]
```
### Editar un accesorio existente

- **Método:** GET,POST  
- **Endpoint:** `/accesorio/editar/<int:id>`

**Descripción:**  
Edita un accesorio existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
  "tipo": "Nuevo tipo del accesorio",
  "modelo_id": "ID del nuevo modelo asociado"
}
]
```
### Eliminar un accesorio

- **Método:** POST  
- **Endpoint:** `/accesorio/borrar/{id}`

**Descripción:**  
Elimina un accesorio existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del accesorio a eliminar
```

## Características

### Listar todas las características

- **Método:** GET  
- **Endpoint:** `/caracteristicas`

**Descripción:**  
Muestra una lista de todas las características.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "tipo": "Color",
        "descripcion": "Rojo",
        "modelo_id": 2
    },
    {
        "id": 2,
        "tipo": "Tamaño",
        "descripcion": "Grande",
        "modelo_id": 3
    }
    // Otros objetos de características
]
```
### Crear una nueva caracteristica

- **Método:** GET,POST  
- **Endpoint:** `/caracteristica/nuevo`

**Descripción:**  
Crea una nueva característica. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "tipo": "Color",
    "descripcion": "Verde",
    "modelo_id": 2
}
]
```
### Editar una caracteristica existente

- **Método:** GET,POST  
- **Endpoint:** `/caracteristica/editar/<int:id>`

**Descripción:**  
Edita una caracteristica existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "tipo": "Tamaño",
    "descripcion": "Mediano",
    "modelo_id": 3
}
]
```
### Eliminar una caracteristica

- **Método:** POST  
- **Endpoint:** `/caracteristica/borrar/{id}`

**Descripción:**  
Elimina una caracteristica existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID de la caracteristica a eliminar
```

## Categorías

### Listar todas las categorías

- **Método:** GET  
- **Endpoint:** `/categorias`

**Descripción:**  
Muestra una lista de todas las categorías.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "nombre": "Electrónica"
    },
    {
        "id": 2,
        "nombre": "Hogar"
    }
    // Otros objetos de categorías
]

```
### Crear una nueva categoria

- **Método:** GET,POST  
- **Endpoint:** `/categoria/nuevo`

**Descripción:**  
Crea una nueva categoria. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Deportes"
}
]
```
### Editar una categoria existente

- **Método:** GET,POST  
- **Endpoint:** `/categoria/editar/<int:id>`

**Descripción:**  
Edita una categoria existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Jardinería"
}
]
```
### Eliminar una categoria

- **Método:** POST  
- **Endpoint:** `/categoria/borrar/{id}`

**Descripción:**  
Elimina una categoria existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID de la categoria a eliminar
```

## Clientes

### Listar todos los clientes

- **Método:** GET  
- **Endpoint:** `/clientes`

**Descripción:**  
Muestra una lista de todos los clientes.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "nombre": "Juan Perez"
    },
    {
        "id": 2,
        "nombre": "Ana López"
    }
    // Otros objetos de cliente
]
```
### Crear un nuevo cliente

- **Método:** GET,POST  
- **Endpoint:** `/cliente/nuevo`

**Descripción:**  
Crea un nuevo cliente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Jorge"
}
]
```
### Editar un cliente existente

- **Método:** GET,POST  
- **Endpoint:** `/cliente/editar/<int:id>`

**Descripción:**  
Edita un cliente existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Samuel"
}
]
```
### Eliminar un cliente

- **Método:** POST  
- **Endpoint:** `/cliente/borrar/{id}`

**Descripción:**  
Elimina un cliente existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del cliente a eliminar
```

## Equipos

### Listar todos los equipos

- **Método:** GET  
- **Endpoint:** `/equipos`

**Descripción:**  
Lista todos los equipos disponibles.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "nombre": "Equipo Alpha",
        "precio": 1500.00,
        "categoria_id": 2,
        "marca_id": 1,
        "modelo_id": 3,
        "caracteristica_id": 4,
        "accesorio_id": 5
    },
    {
        "id": 2,
        "nombre": "Equipo Beta",
        "precio": 2000.00,
        "categoria_id": 1,
        "marca_id": 2,
        "modelo_id": 1,
        "caracteristica_id": 2,
        "accesorio_id": 3
    }
    // Otros objetos de equipo
]

```
### Crear un nuevo equipo

- **Método:** GET,POST  
- **Endpoint:** `/equipo/nuevo`

**Descripción:**  
Crea un nuevo equipo. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Equipo Gamma",
    "precio": 1800.00,
    "categoria_id": 3,
    "marca_id": 2,
    "modelo_id": 4,
    "caracteristica_id": 1,
    "accesorio_id": 2
}
]
```
### Editar un equipo existente

- **Método:** GET,POST  
- **Endpoint:** `/equipo/editar/<int:id>`

**Descripción:**  
Edita un equipo existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Equipo Gamma Pro",
    "precio": 2200.00,
    "categoria_id": 3,
    "marca_id": 2,
    "modelo_id": 4,
    "caracteristica_id": 1,
    "accesorio_id": 2
}
]
```
### Eliminar un equipo

- **Método:** POST  
- **Endpoint:** `/equipo/borrar/{id}`

**Descripción:**  
Elimina un equipo existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del equipo a eliminar
```

## Fabricantes

### Listar todos los fabricantes

- **Método:** GET  
- **Endpoint:** `/fabricantes`

**Descripción:**  
Lista todos los fabricantes registrados en el sistema.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "nombre": "Fabricante A",
        "pais_origen": "Argentina"
    },
    {
        "id": 2,
        "nombre": "Fabricante B",
        "pais_origen": "Brasil"
    }
]
```
### Crear un nuevo fabricante

- **Método:** GET,POST  
- **Endpoint:** `/fabricante/nuevo`

**Descripción:**  
Crea un nuevo fabricante. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Fabricante C",
    "pais_origen": "México"
}
]
```
### Editar un fabricante existente

- **Método:** GET,POST  
- **Endpoint:** `/fabricante/editar/<int:id>`

**Descripción:**  
Edita un fabricante existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Fabricante C Updated",
    "pais_origen": "Colombia"
}
]
```
### Eliminar un fabricante

- **Método:** POST  
- **Endpoint:** `/fabricate/borrar/{id}`

**Descripción:**  
Elimina un fabricante existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del fabricante a eliminar
```

## Marcas

### Listar todas las marcas

- **Método:** GET  
- **Endpoint:** `/marcas`

**Descripción:**  
Lista todas las marcas registradas en el sistema.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "nombre": "Marca A"
    },
    {
        "id": 2,
        "nombre": "Marca B"
    }
]
```
### Crear una nueva marca

- **Método:** GET,POST  
- **Endpoint:** `/marca/nuevo`

**Descripción:**  
Crea una nueva marca. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Motorola"
}
]
```
### Editar una marca existente

- **Método:** GET,POST  
- **Endpoint:** `/marca/editar/<int:id>`

**Descripción:**  
Edita una marca existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Samsung",
}
]
```
### Eliminar una marca

- **Método:** POST  
- **Endpoint:** `/marca/borrar/{id}`

**Descripción:**  
Elimina una marca existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID de la marca a eliminar
```

## Modelos

### Listar todos los modelos

- **Método:** GET  
- **Endpoint:** `/modelos`

**Descripción:**  
Lista todos los modelos registrados en el sistema.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "nombre": "Modelo X",
        "fabricante_id": 2
    },
    {
        "id": 2,
        "nombre": "Modelo Y",
        "fabricante_id": 3
    }
]
```
### Crear un nuevo modelo

- **Método:** GET,POST  
- **Endpoint:** `/modelo/nuevo`

**Descripción:**  
Crea un nuevo modelo. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
   "nombre": "Modelo X",
    "fabricante_id": 5
}
]
```
### Editar un modelo existente

- **Método:** GET,POST  
- **Endpoint:** `/modelo/editar/<int:id>`

**Descripción:**  
Edita un modelo existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Modelo A",
    "fabricante_id": 6
}
]
```
### Eliminar un modelo

- **Método:** POST  
- **Endpoint:** `/modelo/borrar/{id}`

**Descripción:**  
Elimina un modelo existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del modelo a eliminar
```

## Proveedores

### Listar todos los proveedores

- **Método:** GET  
- **Endpoint:** `/proveedores`

**Descripción:**  
Lista todos los proveedores registrados en el sistema.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "nombre": "Proveedor A",
        "contacto": "contacto@proveedora.com"
    },
    {
        "id": 2,
        "nombre": "Proveedor B",
        "contacto": "contacto@proveedorb.com"
    }
]
```
### Crear un nuevo proveedor

- **Método:** GET,POST  
- **Endpoint:** `/proveedor/nuevo`

**Descripción:**  
Crea un nuevo proveedor. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Proveedor C",
    "contacto": "contacto@proveedorc.com"
}
]
```
### Editar un proveedor existente

- **Método:** GET,POST  
- **Endpoint:** `/proveedor/editar/<int:id>`

**Descripción:**  
Edita un proveedor existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
    "nombre": "Proveedor D",
    "contacto": "contacto@proveedord.com"
}
]
```
### Eliminar un proveedor

- **Método:** POST  
- **Endpoint:** `/proveedor/borrar/{id}`

**Descripción:**  
Elimina un proveedor existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del proveedor a eliminar
```

## Stocks

### Listar todos los stocks

- **Método:** GET  
- **Endpoint:** `/stocks`

**Descripción:**  
Lista todos los registros de stock en el sistema.

**Ejemplo de respuesta:**
```html
[
    {
        "id": 1,
        "cantidad": 100,
        "ubicacion": "Almacén A",
        "equipo_id": 1
    },
    {
        "id": 2,
        "cantidad": 50,
        "ubicacion": "Almacén B",
        "equipo_id": 2
    }
]
```
### Crear un nuevo stock

- **Método:** GET,POST  
- **Endpoint:** `/stock/nuevo`

**Descripción:**  
Crea un nuevo stock. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
        "cantidad": 5,
        "ubicacion": "Almacén A",
        "equipo_id": 4
}
]
```
### Editar un stock existente

- **Método:** GET,POST  
- **Endpoint:** `/stock/editar/<int:id>`

**Descripción:**  
Edita un stock existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
        "cantidad": 12,
        "ubicacion": "Almacén C",
        "equipo_id": 7
}
]
```
### Eliminar un stock

- **Método:** POST  
- **Endpoint:** `/stock/borrar/{id}`

**Descripción:**  
Elimina un stock existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del stock a eliminar
```

- **Método:** GET,POST  
- **Endpoint:** `/stock/editar/<int:id>`

**Descripción:**  
Edita un stock existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
[
{
        "cantidad": 12,
        "ubicacion": "Almacén C",
        "equipo_id": 7
}
]
```
### Eliminar un stock

- **Método:** POST  
- **Endpoint:** `/stock/borrar/{id}`

**Descripción:**  
Elimina un stock existente. Solo accesible para usuarios administradores.

**Ejemplo de respuesta:**

```html
Parámetros de la URL:

id: ID del stock a eliminar
```

