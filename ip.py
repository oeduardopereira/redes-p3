import struct

from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        # primeiro separa o cabeçalho do resto do datagrama
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # é para mim, então entrego para a camada de cima
            if proto == IPPROTO_TCP and self.callback is not None:
                self.callback(src_addr, dst_addr, payload)
            return

        # se não é para mim, tenho que repassar (estou fazendo papel de roteador)
        #
        # o ttl é decrementado a cada roteador. ttl 1 significa que esse é o
        # último salto possível, então o pacote tem que ser descartado aqui
        # em vez de ser encaminhado com ttl zero
        ttl = ttl - 1
        if ttl <= 0:
            return

        # bytes são imutáveis, então uso um bytearray para poder alterar o pacote
        pacote = bytearray(datagrama)
        pacote[8] = ttl

        # o checksum do cabeçalho depende do ttl, então tenho que zerar o campo
        # e calcular ele de novo, senão o próximo roteador vai descartar o pacote
        pacote[10] = 0
        pacote[11] = 0
        tamanho_cabecalho = (pacote[0] & 0x0F) * 4
        checksum = calc_checksum(bytes(pacote[:tamanho_cabecalho]))
        pacote[10:12] = struct.pack('!H', checksum)

        next_hop = self._next_hop(dst_addr)
        self.enlace.enviar(bytes(pacote), next_hop)

    def _next_hop(self, dest_addr):
        destino = struct.unpack('!I', str2addr(dest_addr))[0]

        # vou guardando o candidato com o maior prefixo encontrado até agora
        melhor_next_hop = None
        maior_prefixo = -1

        for cidr, next_hop in self.tabela:
            rede_str, prefixo_str = cidr.split('/')
            prefixo = int(prefixo_str)

            # monta uma máscara com "prefixo" bits 1 seguidos de zeros
            mascara = ((1 << prefixo) - 1) << (32 - prefixo)
            rede = struct.unpack('!I', str2addr(rede_str))[0]

            if (destino & mascara) == (rede & mascara):
                # se casar com mais de uma entrada, a mais específica ganha
                if prefixo > maior_prefixo:
                    maior_prefixo = prefixo
                    melhor_next_hop = next_hop

        return melhor_next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # por enquanto guardo a tabela do jeito que veio mesmo, e faço a
        # conversão na hora de procurar o next_hop
        self.tabela = list(tabela)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        if self.meu_endereco is None:
            origem = '0.0.0.0'
        else:
            origem = self.meu_endereco

        # cabeçalho IPv4 sem opções: versão 4, ihl 5, tos 0, etc.
        # o checksum começa zerado porque só dá para calcular depois de montar
        # o cabeçalho inteiro
        versao_ihl = 0x45
        dscp_ecn = 0
        tamanho_total = 20 + len(segmento)
        identificacao = 0
        flags_offset = 0
        ttl = 64
        protocolo = IPPROTO_TCP
        checksum = 0

        cabecalho = struct.pack('!BBHHHBBHII',
                                versao_ihl, dscp_ecn, tamanho_total,
                                identificacao, flags_offset, ttl,
                                protocolo, checksum,
                                struct.unpack('!I', str2addr(origem))[0],
                                struct.unpack('!I', str2addr(dest_addr))[0])

        # calcula o checksum com o campo zerado e depois coloca ele no lugar
        checksum = calc_checksum(cabecalho)
        cabecalho = cabecalho[:10] + struct.pack('!H', checksum) + cabecalho[12:]

        datagrama = cabecalho + segmento
        self.enlace.enviar(datagrama, next_hop)
