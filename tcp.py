import asyncio
from tcputils import *
import random

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None # Callback da camada de aplicação do servidor
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('Servidor: descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = Conexao(self, id_conexao, seq_no)
            self.conexoes[id_conexao] = conexao
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)


class Conexao:
    def __init__(self, servidor, id_conexao, client_initial_seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao 
        self.callback = None 
        
        self.client_isn = client_initial_seq_no

        self.server_isn = random.randint(0, 0xFFFF) 

        self.snd_una = self.server_isn
        self.snd_nxt = self.server_isn + 1
        self.rcv_nxt = self.client_isn + 1
        self.estado = "SYN_RCVD"

        self._send_syn_ack()

    def _send_syn_ack(self):
        """
        Constrói e envia um segmento SYN+ACK para o cliente.
        """
        client_addr, client_port, server_addr_rcvd_on, server_port_rcvd_on = self.id_conexao
        
        flags_syn_ack = FLAGS_SYN | FLAGS_ACK
        
        header_syn_ack = make_header(
            src_port=server_port_rcvd_on,
            dst_port=client_port,
            seq_no=self.server_isn,
            ack_no=self.rcv_nxt,
            flags=flags_syn_ack
        )
        
        segment_syn_ack = fix_checksum(header_syn_ack, server_addr_rcvd_on, client_addr)
        self.servidor.rede.enviar(segment_syn_ack, client_addr)

    def _send_ack(self):
        """
        Envia um segmento ACK puro para o cliente.
        Usado para confirmar dados recebidos ou o ACK final do handshake.
        """
        client_addr, client_port, server_addr_rcvd_on, server_port_rcvd_on = self.id_conexao

        header_ack = make_header(
            src_port=server_port_rcvd_on,
            dst_port=client_port,
            seq_no=self.snd_nxt, 
            ack_no=self.rcv_nxt,
            flags=FLAGS_ACK
        )

        segment_ack = fix_checksum(header_ack, server_addr_rcvd_on, client_addr)
        self.servidor.rede.enviar(segment_ack, client_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        ack_flag_present = (flags & FLAGS_ACK) == FLAGS_ACK
        ack_needed_for_this_segment = False

        if ack_flag_present:
            if self.estado == "SYN_RCVD":
                if ack_no == self.snd_nxt:
                    self.snd_una = ack_no
                    self.estado = "ESTABLISHED"
                    ack_needed_for_this_segment = True
                else:
                    return

            elif self.estado == "ESTABLISHED":
                if self.snd_una < ack_no <= self.snd_nxt:
                    self.snd_una = ack_no
                    if not payload:
                        ack_needed_for_this_segment = True
                elif ack_no <= self.snd_una:
                    pass
                else:
                    return
                
        if payload:
            if self.estado == "ESTABLISHED":
                if seq_no == self.rcv_nxt:
                    if self.callback:
                        self.callback(self, payload)
                    self.rcv_nxt += len(payload)
                ack_needed_for_this_segment = True

        if ack_needed_for_this_segment:
            self._send_ack()


    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos NESTA CONEXÃO.
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        # Lembre-se de atualizar self.snd_nxt, lidar com acknowledgements e retransmissões.
        print(f"Conexao {self.id_conexao}: Camada de aplicação pediu para enviar: {dados!r} (NÃO IMPLEMENTADO)")
        pass

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão (envio de FIN, etc.)
        print(f"Conexao {self.id_conexao}: Camada de aplicação pediu para fechar a conexão. (NÃO IMPLEMENTADO)")
        pass

