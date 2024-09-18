import nmap
import re
from tqdm import tqdm
import time

def validar_red_o_ip(entrada):
    # Validar si la entrada es una dirección de red (e.g., 192.168.1.0/24) o una IP (e.g., 192.168.1.1)
    patron_red = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$")
    patron_ip = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(patron_red.match(entrada) or patron_ip.match(entrada))

def escanear_red(red):
    scanner = nmap.PortScanner()
    print(f"Escaneando la red {red} con ARP Ping...\n")
    scanner.scan(hosts=red, arguments='-sn -PR')  # Usamos -PR para realizar un ARP Ping

    # Progreso del escaneo
    hosts_activos = []
    for host in tqdm(scanner.all_hosts(), desc="Escaneando red", unit="host"):
        if scanner[host]['status']['state'] == 'up':
            mac = scanner[host]['addresses'].get('mac', 'MAC desconocido')
            hosts_activos.append((host, mac))
        time.sleep(0.1)  # Simulación de progreso, no necesario en una implementación real

    if hosts_activos:
        print("\nIPs activas encontradas (IP - MAC):")
        for i, (host, mac) in enumerate(hosts_activos, 1):
            print(f"{i}. {host} - {mac}")
    else:
        print("No se encontraron hosts activos.")
    
    return hosts_activos

def escanear_puertos(ip):
    scanner = nmap.PortScanner()
    print(f"\nEscaneando puertos de la IP {ip}...\n")

    # Progreso del escaneo
    with tqdm(total=100, desc="Escaneando puertos", unit="porcentaje") as pbar:
        scanner.scan(ip, arguments='-sV')
        for _ in range(100):  # Simulación de progreso
            time.sleep(0.05)
            pbar.update(1)

    if ip in scanner.all_hosts():
        resultados = []
        print(f"\nNmap scan report for {ip}")
        print(f"Host is up.")
        for proto in scanner[ip].all_protocols():
            lport = sorted(scanner[ip][proto].keys())
            for port in lport:
                state = scanner[ip][proto][port]['state']
                service = scanner[ip][proto][port]['name']
                version = scanner[ip][proto][port].get('version', 'Desconocida')
                resultado = f"{port}/tcp {state} {service} {version}"
                resultados.append(resultado)

        if resultados:
            print("\nPuertos abiertos y servicios encontrados:")
            for resultado in resultados:
                print(resultado)
        else:
            print("No se encontraron puertos abiertos o servicios en ejecución.")
        
        # Mostrar la dirección MAC si está disponible
        mac = scanner[ip]['addresses'].get('mac', 'MAC desconocido')
        if mac:
            print(f"MAC Address: {mac} ({scanner[ip]['vendor'].get(mac, 'Desconocido')})")
    else:
        print("La IP no es válida o no está activa.")

def main():
    # Solicitar la red o IP para escanear
    red = input("Ingresa la red a escanear (e.g., 192.168.1.0/24) o una IP (e.g., 192.168.1.1): ")
    if not validar_red_o_ip(red):
        print("Formato de red o IP inválido. Usa un formato como 192.168.1.0/24 o 192.168.1.1.")
        return

    # Escanear la red y mostrar las IPs activas con sus MAC
    hosts_activos = escanear_red(red)

    if not hosts_activos:
        print("No se encontraron IPs activas. Terminando el programa.")
        return

    while True:
        print("\nOpciones disponibles:")
        print("1. Escanear puertos de una IP seleccionada.")
        print("2. Escanear todos los puertos de todas las IPs activas.")
        print("3. Salir.")
        opcion = input("Selecciona una opción (1/2/3): ")

        if opcion == '1':
            # Solicitar al usuario seleccionar una IP o ingresar manualmente una IP para escanear puertos
            ip = input("\nSelecciona el número de la IP de la lista para escanear puertos o ingresa una IP manualmente: ")
            if ip.isdigit():
                indice = int(ip) - 1
                if 0 <= indice < len(hosts_activos):
                    ip = hosts_activos[indice][0]
                else:
                    print("Opción inválida.")
                    continue
            else:
                if not validar_red_o_ip(ip):
                    print("Formato de IP inválido.")
                    continue
            
            # Escanear puertos de la IP seleccionada o ingresada
            escanear_puertos(ip)

        elif opcion == '2':
            # Escanear todos los puertos de todas las IPs activas
            for host, _ in hosts_activos:
                escanear_puertos(host)
        
        elif opcion == '3':
            print("Saliendo del programa.")
            break
        
        else:
            print("Opción inválida. Intenta de nuevo.")
            continue

        # Preguntar si desea escanear otro puerto o salir
        continuar = input("\n¿Deseas escanear otra IP? (s/n): ")
        if continuar.lower() != 's':
            print("Saliendo del programa.")
            break

if __name__ == "__main__":
    main()
