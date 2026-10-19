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
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        dest = struct.unpack('!I', str2addr(dest_addr))[0]
        # fica com a entrada de prefixo mais longo que casar
        escolhido = None
        bits_escolhido = -1
        for rede, mascara, bits, next_hop in self.tabela:
            if (dest & mascara) == rede and bits > bits_escolhido:
                bits_escolhido = bits
                escolhido = next_hop
        return escolhido

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
        # guardo já com a rede e a máscara em número, para facilitar na hora
        # de comparar com o endereço de destino
        self.tabela = []
        for cidr, next_hop in tabela:
            endereco, prefixo = cidr.split('/')
            prefixo = int(prefixo)
            mascara = (0xffffffff << (32 - prefixo)) & 0xffffffff if prefixo else 0
            rede = struct.unpack('!I', str2addr(endereco))[0] & mascara
            self.tabela.append((rede, mascara, prefixo, next_hop))

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
        # a camada de cima é o TCP, então monta o cabeçalho IP na mão
        if self.meu_endereco is None:
            src_addr = '0.0.0.0'
        else:
            src_addr = self.meu_endereco
        total_len = 20 + len(segmento)
        cabecalho = struct.pack('!BBHHHBBHII',
                                0x45, 0, total_len, 0, 0,
                                64, IPPROTO_TCP, 0,
                                struct.unpack('!I', str2addr(src_addr))[0],
                                struct.unpack('!I', str2addr(dest_addr))[0])
        # calcula o checksum com o campo zerado e depois coloca ele no lugar
        checksum = calc_checksum(cabecalho)
        cabecalho = cabecalho[:10] + struct.pack('!H', checksum) + cabecalho[12:]
        datagrama = cabecalho + segmento
        self.enlace.enviar(datagrama, next_hop)
