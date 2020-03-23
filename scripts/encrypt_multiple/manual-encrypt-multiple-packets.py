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
message="FRAME1FRAME1FRAME1FRAME1FRAME1FRAME1FRAME2FRAME2FRAME2FRAME2FRAME2FRAME2FRAME3FRAME3FRAME3FRAME3FRAME3FRAME3"

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'


# On calcule le nombre de fragments que l'on aura à envoyer
nbFragments = int(math.ceil(len(message) / 36))

#Initialisation du tableaux contenants les fragments
arps = []


for i in range(0, nbFragments):
    # lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
    arp = rdpcap('arp.cap')[0]

    # On ajoute le numero de fragment
    arp.SC = i

    # On met le bit "More fragments" à 1 pour tous les fragments sauf le dernier
    if i < (nbFragments - 1):
        arp.FCfield = arp.FCfield | 0x4

    # On recupère la partie du message à envoyer
    fragMessage = message[i * 36:((i+1) * 36)]

    # On calcule le nouveau ICV
    icvMessage = zlib.crc32(fragMessage.encode()) & 0xffffffff

    payload = fragMessage.encode()+struct.pack('<L', icvMessage)

    # rc4 seed est composé de IV+clé
    seed = arp.iv+key

    # On instancie l'objet RC4
    cipher = RC4(seed, streaming=True)

    # On chiffre le payload
    cipherText = cipher.crypt(payload)

    # On recupere l'ICV
    encrypted_icv = struct.unpack('!L', cipherText[-4:])[0]

    # Affichage des différentes informations concernant le fragment actuel
    print("Fragment #"+str(i))
    print('Fragment content to encrypt : ' + fragMessage + ' with the ICV ' +'{:x}'.format(icvMessage))
    print('Encrypted content : ' + cipherText[:-4].hex() + ' and the encrypted ICV is ' + cipherText[-4:].hex()+"\n")

    # On ecrit le contenu et l'ICV
    arp.wepdata = cipherText[:-4]
    arp.icv = encrypted_icv

    # On append le fragment actuel
    arps.append(arp)

print("Sent " + str(nbFragments) + " fragments")

# On ecrit les fragments
wrpcap("output_multiple.pcap", arps)