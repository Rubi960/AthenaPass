import os
import argparse
import requests
import srp        # implementación del protocolo SRP para autenticación

import warnings
warnings.filterwarnings("ignore")

# parsear argumentos de línea de comandos
parser = argparse.ArgumentParser(description="Cliente AthenaPass")
parser.add_argument("--server", default=None, help="URL del servidor (ej: http://192.168.1.100:4134 o https://example.com:4134)")
parser.add_argument("--insecure", action="store_true", help="Desactivar verificación de certificado SSL (para certs autofirmados)")
args = parser.parse_args()

# determinar URL del servidor
if args.server:
    SERVER = args.server
else:
    USE_HTTPS = os.environ.get("USE_HTTPS", "0") in ("1", "true", "True")
    SERVER = "https://localhost:4134" if USE_HTTPS else "http://localhost:4134"

# verificación SSL: desactivar si flag --insecure o si usar certs
VERIFY = not args.insecure and not os.environ.get("USE_HTTPS", "0") in ("1", "true", "True")

def register(username, password):
    # crear salt SRP y verificador usando la contraseña en plano
    salt, vkey = srp.create_salted_verification_key(username, password)

    # enviar datos de registro al servidor
    r = requests.post(f"{SERVER}/register", json={
        "username": username,
        "salt": salt.hex(),
        "vkey": vkey.hex()
    }, verify=VERIFY)

    print("Register:", r.json())


def authenticate(username, password):
    # crear objeto User que realizará los cálculos SRP
    usr = srp.User(username, password)

    # iniciar el protocolo de autenticación, A se envía al servidor
    uname, A = usr.start_authentication()

    # enviar A al servidor y recibir salt y B
    r = requests.post(f"{SERVER}/auth/start", json={
        "username": uname,
        "A": A.hex()
    }, verify=VERIFY)
    data = r.json()
    print("Start:", data)

    s = bytes.fromhex(data["salt"])
    B = bytes.fromhex(data["B"])

    # calcular prueba M del desafío
    M = usr.process_challenge(s, B)
    if M is None:
        raise Exception("process_challenge falló")

    # enviar prueba M al servidor y obtener HAMK y token
    r = requests.post(f"{SERVER}/auth/finish", json={
        "username": username,
        "M": M.hex()
    }, verify=VERIFY)
    data = r.json()
    print("Finish:", data)

    HAMK = bytes.fromhex(data["HAMK"])
    token = data.get("token")
    if token is None:
        raise Exception("no token received from server")

    # verificar la prueba del servidor para completar la autenticación
    usr.verify_session(HAMK)

    print("Cliente autenticado?:", usr.authenticated())
    return token


if __name__ == "__main__":
    username = "alice"
    password = "testpassword"

    register(username, password)
    token = authenticate(username, password)

    # las solicitudes incluyen el bearer token
    headers = {"Authorization": f"Bearer {token}"}

    def list_passwords():
        # obtener todas las entradas almacenadas para el usuario autenticado
        r = requests.get(f"{SERVER}/passwords", headers=headers, verify=VERIFY)
        print("Passwords:", r.json())

    def add_password(entry_id, encrypted_value):
        # crear una nueva entrada de contraseña cifrada
        r = requests.post(f"{SERVER}/passwords", json={
            "id": entry_id,
            "value": encrypted_value
        }, headers=headers, verify=VERIFY)
        print("Add:", r.json())

    def update_password(entry_id, encrypted_value):
        # modificar una entrada existente
        r = requests.put(f"{SERVER}/passwords/{entry_id}", json={
            "value": encrypted_value
        }, headers=headers, verify=VERIFY)
        print("Update:", r.json())

    def delete_password(entry_id):
        # eliminar una entrada por id
        r = requests.delete(f"{SERVER}/passwords/{entry_id}", headers=headers, verify=VERIFY)
        print("Delete:", r.json())

    # demostración mínima
    print(f"\nConectando a: {SERVER}")
    print(f"Verificación SSL: {VERIFY}\n")
    
    add_password("gmail", "ciphertext1")
    add_password("bank", "ciphertext2")
    list_passwords()
    update_password("gmail", "ciphertext1-updated")
    delete_password("bank")
    list_passwords()
