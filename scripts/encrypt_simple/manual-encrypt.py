#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Edin Mujkanovic et Daniel Oliveira Paiva"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "edin.mujkanovic@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from rc4 import RC4
import zlib


# Message à chiffrer
message="FRAME1FRAME1FRAME1FRAME1FRAME1FRAME1"

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# On calcule le nouveau icv du message sur 32bits
icvMessage = zlib.crc32(message.encode()) & 0xffffffff

#On crée le payload avec le message + l'ICV
payload = message.encode()+struct.pack('<L', icvMessage)

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# Instanciation de l'objet RC4
cipher = RC4(seed, streaming=True)

# Chiffrement du payload
cipherText = cipher.crypt(payload)

#On recupère l'ICV contenu dans le ciphertext.
encrypted_icv = struct.unpack('!L', cipherText[-4:])[0]

# Affichage des différentes informations concernant le fragment actuel
print('Message to encrypt : ' + message + ' with the ICV ' +'{:x}'.format(icvMessage))
print('Encrypted message : ' + cipherText[:-4].hex() + ' and the encrypted ICV is ' + cipherText[-4:].hex())

# On ecrit les données ainsi que l'ICV
arp.wepdata = cipherText[:-4]
arp.icv = encrypted_icv

# Ecriture du fichier final
wrpcap("output.pcap", arp)