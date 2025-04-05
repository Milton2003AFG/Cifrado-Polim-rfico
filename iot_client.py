
# Importaciones 
import random  # Para generación de números aleatorios/primos
import struct  # Para empaquetar datos en binario
import json    # Para guardar datos en formato legible
from enum import Enum  # Para manejar tipos de mensaje

# Definición de tipos de mensaje usando enumeración
class TipoMensaje(Enum):
    """Tipos de mensajes disponibles en el protocolo"""
    FCM = 0  # First Contact Message (Establecer conexión)
    RM = 1   # Regular Message (Mensaje cifrado)
    KUM = 2  # Key Update Message (Actualizar llaves)
    LCM = 3  # Last Contact Message (Terminar conexión)

class ClienteIoT:
    """Clase principal que implementa el cliente IoT"""
    
    def __init__(self):
        """Inicializa el cliente con valores por defecto"""
        # Identificador único del dispositivo (6 bits)
        self.id = random.randint(0, 63)
        
        # Tabla de llaves para cifrado
        self.llaves = []
        
        # Índice de la llave actual a usar
        self.llave_actual = 0
        
        # Parámetros criptográficos
        self.p = 0  # Número primo P
        self.q = 0  # Número primo Q
        self.s = 0  # Semilla S

    # --- Métodos para generación de números primos ---
    def generar_primo(self, bits=16):
        """
        Genera un número primo de bits 
        """
        while True:
            # Generar número aleatorio
            num = random.getrandbits(bits)
            
            # Verificar si es primo (chequeando divisibilidad)
            if num > 1 and all(num % i != 0 for i in [2, 3, 5, 7, 11, 13]):
                return num

    # --- Funciones criptográficas ---
    def funcion_mezcla(self, x, y):
        """
        Función scrambled: Combina dos valores (P y S)
        Operaciones:
        1. XOR entre x e y
        2. Suma con ((x AND mascara) OR (y desplazado))
        """
        return (x ^ y) + ((x & 0xFFFF) | (y << 16))
    
    def funcion_generacion(self, x, y):
        """
        Genera llave usando:
        1. Rotación de bits de x (32 bits a derecha)
        2. XOR con y
        """
        rotado = ((x >> 32) | (x << 32)) & 0xFFFFFFFFFFFFFFFF
        return rotado ^ y
    
    def funcion_mutacion(self, x, y):
        """
        Actualiza la semilla para próxima generación
        Operaciones:
        1. Suma x + y
        2. XOR con ((x desplazado) OR (y desplazado))
        """
        return (x + y) ^ ((x << 8) | (y >> 8))

    # --- Generación de llaves ---
    def generar_llaves(self):
        """Genera la tabla de llaves usando P, Q y S"""
        self.llaves = []  # Reiniciar tabla
        s = self.s       # Usar semilla actual
        
        print("\n[GENERACIÓN DE LLAVES]")
        print(f"P = {self.p} (bin: {bin(self.p)})")
        print(f"Q = {self.q} (bin: {bin(self.q)})")
        print(f"Semilla inicial S = {s} (bin: {bin(s)})")
        
        # Generar 4 llaves
        for i in range(4):
            # Paso 1: Mezclar P y S
            p0 = self.funcion_mezcla(self.p, s)
            
            # Paso 2: Generar llave
            llave = self.funcion_generacion(p0, self.q)
            self.llaves.append(llave)
            
            # Paso 3: Actualizar semilla
            s = self.funcion_mutacion(s, self.q)
            
            # Mostrar detalles
            print(f"\nLlave K{i+1}:")
            print(f"P0 = f_mezcla(P, S) = {p0} (bin: {bin(p0)})")
            print(f"K{i+1} = f_generacion(P0, Q) = {llave} (bin: {bin(llave)})")
            print(f"Nueva semilla S = f_mutacion(S, Q) = {s} (bin: {bin(s)})")

    # --- Manejo de mensajes ---
    def crear_fcm(self):
        """
        Crea mensaje de primer contacto (FCM)
        Contiene: ID, P, Q, S para generar llaves
        """
        # Generar parámetros iniciales
        self.p = self.generar_primo()
        self.q = self.generar_primo()
        self.s = random.getrandbits(64)
        
        # Generar tabla de llaves
        self.generar_llaves()
        
        # Crear archivo binario
        with open('fcm.bin', 'wb') as f:
            # Cabecera: ID (6 bits) + Tipo (2 bits)
            f.write(struct.pack('B', (self.id << 2) | TipoMensaje.FCM.value))
            # Parámetros P, Q, S (cada uno 64 bits)
            f.write(struct.pack('QQQ', self.p, self.q, self.s))
        
        # Crear archivo JSON para visualización
        datos = {
            "id": self.id,
            "tipo": "FCM",
            "parametros": {
                "p": self.p,
                "q": self.q,
                "s": self.s,
                "p_bin": bin(self.p),
                "q_bin": bin(self.q),
                "s_bin": bin(self.s)
            },
            "llaves_generadas": [hex(k) for k in self.llaves],
            "descripcion": "Mensaje de primer contacto con parametros para generar llaves compartidas"
        }
        with open('fcm.json', 'w') as f:
            json.dump(datos, f, indent=2)
        
        print("\n[FCM CREADO] Valores guardados en fcm.json")

    def cifrar_mensaje(self, mensaje, llave):
        """
        Cifra un mensaje usando:
        1. XOR con llave
        2. Rotación de bits
        """
        # Asegurar mensaje de 8 bytes (64 bits)
        datos = mensaje.encode('utf-8').ljust(8, b'\x00')[:8]
        num = int.from_bytes(datos, 'big')  # Convertir a número
        
        # Aplicar operaciones criptográficas
        num ^= llave  # Operación XOR con llave
        num = ((num >> 4) | (num << 60)) & 0xFFFFFFFFFFFFFFFF  # Rotación 4 bits derecha
        
        return num

    def crear_rm(self, mensaje):
        """Crea mensaje regular cifrado (RM)"""
        if not self.llaves:
            print("Error: Primero debe generar FCM")
            return
        
        # Obtener llave actual
        llave = self.llaves[self.llave_actual]
        
        # Cifrar mensaje
        cifrado = self.cifrar_mensaje(mensaje, llave)
        
        # Guardar en binario
        with open('rm.bin', 'wb') as f:
            f.write(struct.pack('B', (self.id << 2) | TipoMensaje.RM.value))  # Cabecera
            f.write(struct.pack('B', self.llave_actual))  # Índice llave
            f.write(struct.pack('Q', cifrado))  # Mensaje cifrado
        
        # Guardar en JSON
        datos = {
            "id": self.id,
            "tipo": "RM",
            "llave_usada": {
                "indice": self.llave_actual,
                "valor": hex(llave),
                "valor_bin": bin(llave)
            },
            "mensaje_original": mensaje,
            "mensaje_cifrado": {
                "hex": hex(cifrado),
                "bin": bin(cifrado)
            },
            "proceso_cifrado": [
                "1. Convertir mensaje a numero de 64 bits",
                "2. Aplicar XOR con llave",
                "3. Rotar 4 bits a la derecha"
            ]
        }
        with open('rm.json', 'w') as f:
            json.dump(datos, f, indent=2)
        
        print("\n[RM CREADO] Detalles en rm.json")
        
        # Rotar llave para próximo mensaje
        self.llave_actual = (self.llave_actual + 1) % 4

    def crear_kum(self):
        """Crea mensaje de actualización de llaves (KUM)"""
        # Generar nuevos parámetros
        self.p = self.generar_primo()
        self.q = self.generar_primo()
        self.s = random.getrandbits(64)
        
        # Generar nuevas llaves
        self.generar_llaves()
        
        # Guardar en binario
        with open('kum.bin', 'wb') as f:
            f.write(struct.pack('B', (self.id << 2) | TipoMensaje.KUM.value))
            f.write(struct.pack('QQQ', self.p, self.q, self.s))
        
        # Guardar en JSON
        datos = {
            "id": self.id,
            "tipo": "KUM",
            "nuevos_parametros": {
                "p": self.p,
                "q": self.q,
                "s": self.s
            },
            "nuevas_llaves": [hex(k) for k in self.llaves],
            "descripcion": "Actualizacion de parametros y llaves"
        }
        with open('kum.json', 'w') as f:
            json.dump(datos, f, indent=2)
        
        print("\n[KUM CREADO] Nuevas llaves en kum.json")

    def crear_lcm(self):
        """Crea mensaje de último contacto (LCM)"""
        # Solo necesita cabecera con ID y tipo
        with open('lcm.bin', 'wb') as f:
            f.write(struct.pack('B', (self.id << 2) | TipoMensaje.LCM.value))
        
        # Guardar en JSON
        datos = {
            "id": self.id,
            "tipo": "LCM",
            "descripcion": "Solicitud de terminacion de conexion"
        }
        with open('lcm.json', 'w') as f:
            json.dump(datos, f, indent=2)
        
        # Limpiar estado
        self.llaves = []
        print("\n[LCM CREADO] Conexion terminada. Detalles en lcm.json")

# --- Interfaz de usuario ---
def main():
    """Función principal con menú interactivo"""
    cliente = ClienteIoT()
    
    while True:
        print("\n=== MENÚ CLIENTE IoT ===")
        print("1. Primer contacto (FCM)")
        print("2. Enviar mensaje (RM)")
        print("3. Actualizar llaves (KUM)")
        print("4. Terminar conexión (LCM)")
        print("5. Salir")
        
        opcion = input("Seleccione opción: ")
        
        if opcion == "1":
            cliente.crear_fcm()
        elif opcion == "2":
            if not cliente.llaves:
                print("Primero debe establecer conexión (FCM)")
                continue
            msg = input("Ingrese mensaje (max 8 caracteres): ")
            cliente.crear_rm(msg)
        elif opcion == "3":
            if not cliente.llaves:
                print("Primero debe establecer conexión (FCM)")
                continue
            cliente.crear_kum()
        elif opcion == "4":
            if not cliente.llaves:
                print("No hay conexión activa")
                continue
            cliente.crear_lcm()
        elif opcion == "5":
            break
        else:
            print("Opción no válida")

if __name__ == "__main__":
    main()