
import struct
import json
from enum import Enum

# Definición de tipos de mensaje
class TipoMensaje(Enum):
    """Enumera los tipos de mensajes del protocolo"""
    FCM = 0  # First Contact Message
    RM = 1   # Regular Message
    KUM = 2  # Key Update Message
    LCM = 3  # Last Contact Message

class ServidorIoT:
    """Clase principal que implementa el servidor IoT"""
    
    def __init__(self):
        """Inicializa el servidor con diccionario de clientes"""
        # Estructura: {id: {'p': val, 'q': val, 's': val, 'llaves': [k1, k2, k3, k4]}}
        self.clientes = {}

    # --- Funciones criptográficas ---
    def funcion_mezcla(self, x, y):
        """Igual que en cliente: Combina x e y con XOR y operaciones de bits"""
        return (x ^ y) + ((x & 0xFFFF) | (y << 16))
    
    def funcion_generacion(self, x, y):
        """Igual que en cliente: Genera llave con rotación y XOR"""
        rotado = ((x >> 32) | (x << 32)) & 0xFFFFFFFFFFFFFFFF
        return rotado ^ y
    
    def funcion_mutacion(self, x, y):
        """Igual que en cliente: Actualiza semilla para próxima llave"""
        return (x + y) ^ ((x << 8) | (y >> 8))

    # --- Generación de llaves ---
    def generar_llaves(self, p, q, s):
        """
        Genera tabla de llaves usando los 
        parámetros p, q y s iniciales
        """
        llaves = []
        print("\n[GENERANDO LLAVES EN SERVIDOR]")
        print(f"Usando P={p}, Q={q}, S={s}")
        
        for i in range(4):
            # Paso 1: Mezclar P y S
            p0 = self.funcion_mezcla(p, s)
            
            # Paso 2: Generar llave
            llave = self.funcion_generacion(p0, q)
            llaves.append(llave)
            
            # Paso 3: Actualizar semilla
            s = self.funcion_mutacion(s, q)
            
            # Mostrar información
            print(f"K{i+1}: {hex(llave)} (bin: {bin(llave)})")
        
        return llaves

    # --- Procesamiento de mensajes ---
    def procesar_fcm(self):
        """Procesa mensaje de primer contacto (FCM)"""
        try:
            print("\n[PROCESANDO FCM]")
            
            # Leer archivo binario
            with open('fcm.bin', 'rb') as f:
                cabecera = struct.unpack('B', f.read(1))[0]
                p, q, s = struct.unpack('QQQ', f.read(24))
            
            # Extraer ID y tipo de cabecera
            id_cliente = cabecera >> 2
            tipo = cabecera & 0b11
            
            # Validar tipo de mensaje
            if tipo != TipoMensaje.FCM.value:
                print("Error: No es un mensaje FCM válido")
                return
            
            print(f"ID Cliente: {id_cliente}")
            print(f"Parametros recibidos - P: {p}, Q: {q}, S: {s}")
            
            # Generar llaves
            llaves = self.generar_llaves(p, q, s)
            
            # Registrar cliente
            self.clientes[id_cliente] = {
                'p': p,
                'q': q,
                's': s,
                'llaves': llaves
            }
            
            # Guardar datos en JSON
            datos = {
                "id_cliente": id_cliente,
                "parametros": {
                    "p": p,
                    "q": q,
                    "s": s
                },
                "llaves_generadas": [hex(k) for k in llaves],
                "status": "Conexion establecida",
                "descripcion": "Cliente registrado y llaves generadas"
            }
            with open('fcm_server.json', 'w') as f:
                json.dump(datos, f, indent=2)
            
            print("[FCM PROCESADO] Datos en fcm_server.json")
            
        except FileNotFoundError:
            print("Error: No se encontró fcm.bin")

    def descifrar_mensaje(self, cifrado, llave):
        """
        Descifra mensaje aplicando operaciones inversas:
        1. Rotación inversa (4 bits izquierda)
        2. XOR con llave (mismo que cifrado)
        """
        # Rotación inversa
        num = ((cifrado << 4) | (cifrado >> 60)) & 0xFFFFFFFFFFFFFFFF
        # XOR con llave
        num ^= llave
        # Convertir a texto
        return num.to_bytes(8, 'big').decode('utf-8').strip('\x00')

    def procesar_rm(self):
        """Procesa mensaje regular cifrado (RM)"""
        try:
            print("\n[PROCESANDO RM]")
            
            # Leer archivo binario
            with open('rm.bin', 'rb') as f:
                cabecera = struct.unpack('B', f.read(1))[0]
                idx_llave = struct.unpack('B', f.read(1))[0]
                cifrado = struct.unpack('Q', f.read(8))[0]
            
            # Extraer ID y tipo
            id_cliente = cabecera >> 2
            tipo = cabecera & 0b11
            
            # Validar tipo
            if tipo != TipoMensaje.RM.value:
                print("Error: No es un mensaje RM válido")
                return
            
            # Verificar cliente registrado
            if id_cliente not in self.clientes:
                print("Error: Cliente no registrado")
                return
            
            print(f"ID Cliente: {id_cliente}")
            print(f"Índice llave usada: {idx_llave}")
            
            # Obtener llave correspondiente
            llave = self.clientes[id_cliente]['llaves'][idx_llave]
            print(f"Llave usada: {hex(llave)}")
            
            # Descifrar mensaje
            mensaje = self.descifrar_mensaje(cifrado, llave)
            
            # Guardar en JSON
            datos = {
                "id_cliente": id_cliente,
                "llave_usada": {
                    "indice": idx_llave,
                    "valor": hex(llave)
                },
                "mensaje_cifrado": hex(cifrado),
                "mensaje_descifrado": mensaje,
                "proceso_descifrado": [
                    "1. Rotar 4 bits a la izquierda",
                    "2. Aplicar XOR con llave",
                    "3. Convertir bytes a texto"
                ],
                "status": "Mensaje descifrado"
            }
            with open('rm_server.json', 'w') as f:
                json.dump(datos, f, indent=2)
            
            print(f"[MENSAJE DESCIFRADO]: '{mensaje}'")
            print("Detalles en rm_server.json")
            
        except FileNotFoundError:
            print("Error: No se encontró rm.bin")

    def procesar_kum(self):
        """Procesa actualización de llaves (KUM)"""
        try:
            print("\n[PROCESANDO KUM]")
            
            # Leer archivo binario
            with open('kum.bin', 'rb') as f:
                cabecera = struct.unpack('B', f.read(1))[0]
                p, q, s = struct.unpack('QQQ', f.read(24))
            
            # Extraer ID y tipo
            id_cliente = cabecera >> 2
            tipo = cabecera & 0b11
            
            # Validar tipo
            if tipo != TipoMensaje.KUM.value:
                print("Error: No es un mensaje KUM válido")
                return
            
            # Verificar cliente existente
            if id_cliente not in self.clientes:
                print("Error: Cliente no registrado")
                return
            
            print(f"ID Cliente: {id_cliente}")
            print(f"Nuevos parámetros - P: {p}, Q: {q}, S: {s}")
            
            # Generar nuevas llaves
            llaves = self.generar_llaves(p, q, s)
            
            # Actualizar cliente
            self.clientes[id_cliente] = {
                'p': p,
                'q': q, 
                's': s,
                'llaves': llaves
            }
            
            # Guardar en JSON
            datos = {
                "id_cliente": id_cliente,
                "nuevos_parametros": {
                    "p": p,
                    "q": q,
                    "s": s
                },
                "nuevas_llaves": [hex(k) for k in llaves],
                "status": "Llaves actualizadas",
                "descripcion": "Parametros y llaves actualizados"
            }
            with open('kum_server.json', 'w') as f:
                json.dump(datos, f, indent=2)
            
            print("[KUM PROCESADO] Detalles en kum_server.json")
            
        except FileNotFoundError:
            print("Error: No se encontró kum.bin")

    def procesar_lcm(self):
        """Procesa mensaje de último contacto (LCM)"""
        try:
            print("\n[PROCESANDO LCM]")
            
            # Leer archivo binario (solo 1 byte)
            with open('lcm.bin', 'rb') as f:
                cabecera = struct.unpack('B', f.read(1))[0]
            
            # Extraer ID y tipo
            id_cliente = cabecera >> 2
            tipo = cabecera & 0b11
            
            # Validar tipo
            if tipo != TipoMensaje.LCM.value:
                print("Error: No es un mensaje LCM válido")
                return
            
            print(f"ID Cliente: {id_cliente}")
            
            # Eliminar cliente si existe
            if id_cliente in self.clientes:
                del self.clientes[id_cliente]
                status = "Cliente desconectado"
            else:
                status = "Cliente no existia"
            
            # Guardar en JSON
            datos = {
                "id_cliente": id_cliente,
                "status": status,
                "descripcion": "Solicitud de terminacion de conexion procesada"
            }
            with open('lcm_server.json', 'w') as f:
                json.dump(datos, f, indent=2)
            
            print(f"[LCM PROCESADO] {status}. Detalles en lcm_server.json")
            
        except FileNotFoundError:
            print("Error: No se encontró lcm.bin")

# --- Interfaz de usuario ---
def main():
    """Función principal con menú interactivo"""
    servidor = ServidorIoT()
    
    while True:
        print("\n=== MENÚ SERVIDOR IoT ===")
        print("1. Procesar FCM (Primer contacto)")
        print("2. Procesar RM (Mensaje cifrado)")
        print("3. Procesar KUM (Actualizar llaves)")
        print("4. Procesar LCM (Terminar conexión)")
        print("5. Salir")
        
        opcion = input("Seleccione opción: ")
        
        if opcion == "1":
            servidor.procesar_fcm()
        elif opcion == "2":
            servidor.procesar_rm()
        elif opcion == "3":
            servidor.procesar_kum()
        elif opcion == "4":
            servidor.procesar_lcm()
        elif opcion == "5":
            break
        else:
            print("Opción no válida")

if __name__ == "__main__":
    main()