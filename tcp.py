import asyncio
from grader.tcputils import *
import random
import time

# Constantes para o cálculo do Timeout (RFC 6298)
ALPHA = 0.125
BETA = 0.25

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
            conexao = self.conexoes.get(id_conexao)
            if conexao is None:
                servidor_seq_no = random.randint(0, 0xffff)
                conexao = Conexao(self, id_conexao, seq_no, servidor_seq_no)
                self.conexoes[id_conexao] = conexao
                
                header = make_header(dst_port, src_port, conexao.servidor_seq_no, seq_no + 1, FLAGS_SYN | FLAGS_ACK)
                segmento_syn_ack = fix_checksum(header, dst_addr, src_addr)
                
                # Registrar o tempo de envio do SYN+ACK
                conexao.send_times[conexao.servidor_seq_no] = time.time()
                
                conexao.unacked_segments.append((conexao.servidor_seq_no, segmento_syn_ack))
                conexao._iniciar_timer()
                self.rede.enviar(segmento_syn_ack, src_addr)
                conexao.servidor_seq_no += 1
                
                if self.callback:
                    self.callback(conexao)

        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, servidor_seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None
        self.unacked_segments = []
        self.send_buffer = b''
        self.estimated_rtt = None
        self.dev_rtt = None
        
        self.cwnd = MSS  
        self.bytes_acked_this_window = 0
        self.timeout_interval = 0.5
        self.in_recovery = False

        self.servidor_seq_no = servidor_seq_no 
        self.expected_seq_no = seq_no + 1      
        self.state = 'ESTABLISHED'
        self.send_times = {}

    def _update_timeout(self, sample_rtt):

        if self.estimated_rtt is None and sample_rtt < 0.001:
            return

        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2.0
        else:
            self.dev_rtt = (1 - BETA) * self.dev_rtt + BETA * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = (1 - ALPHA) * self.estimated_rtt + ALPHA * sample_rtt

        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

        self.timeout_interval = max(0.2, self.timeout_interval)

    def _iniciar_timer(self):
        self._cancelar_timer()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)

    def _cancelar_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _timeout(self):
        if not self.unacked_segments:
            return

        self.cwnd = max(MSS, self.cwnd // 2)
        print(f"Timeout! Reduzindo cwnd para {self.cwnd} bytes")

        self.in_recovery = True

        seq_to_resend, segment_to_resend = self.unacked_segments[0]
        dest_addr = self.id_conexao[0]
        
        if seq_to_resend in self.send_times:
            del self.send_times[seq_to_resend]
            
        self.servidor.rede.enviar(segment_to_resend, dest_addr)
        print("Timeout! Reenviando segmento...")
        self._iniciar_timer()

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.state == 'CLOSED':
            return

        if (flags & FLAGS_ACK):
            if self.state == 'LAST_ACK' and ack_no == self.servidor_seq_no:
                self.state = 'CLOSED'; self._cancelar_timer(); self.unacked_segments = []; return
            
            acked_segments = []
            remaining_segments = []
            for unacked_seq, segment in self.unacked_segments:
                header_len = 4 * (read_header(segment)[4] >> 12)
                data_len = len(segment) - header_len
                if data_len == 0 and (read_header(segment)[4] & (FLAGS_SYN | FLAGS_FIN)):
                    data_len = 1
                if unacked_seq + data_len <= ack_no:
                    acked_segments.append((unacked_seq, segment))
                else:
                    remaining_segments.append((unacked_seq, segment))
            
            if acked_segments:
                acked_data_len = 0
                for unacked_seq, segment in acked_segments:
                    if unacked_seq in self.send_times:
                        self._update_timeout(time.time() - self.send_times.pop(unacked_seq))
                    header_len = 4 * (read_header(segment)[4] >> 12)
                    acked_data_len += len(segment) - header_len

                if acked_data_len > 0:
                    # Só aumenta a janela se NÃO estiver em modo de recuperação
                    if not self.in_recovery:
                        self.bytes_acked_this_window += acked_data_len
                        if self.bytes_acked_this_window >= self.cwnd:
                            self.cwnd += MSS
                            self.bytes_acked_this_window = 0
                            print(f"Janela inteira ACK'd. Aumentando cwnd para {self.cwnd} bytes")

                self.in_recovery = False

                self.unacked_segments = remaining_segments
                self._cancelar_timer()
                if self.unacked_segments:
                    self._iniciar_timer()
                
                self._try_send()

        if self.state in ['ESTABLISHED', 'CLOSE_WAIT']:
            if seq_no == self.expected_seq_no:
                should_send_ack = False
                if len(payload) > 0:
                    self.expected_seq_no += len(payload)
                    if self.callback: self.callback(self, payload)
                    should_send_ack = True
                if (flags & FLAGS_FIN):
                    self.state = 'CLOSE_WAIT'
                    self.expected_seq_no += 1
                    if self.callback: self.callback(self, b'')
                    should_send_ack = True
                if should_send_ack:
                    header = make_header(self.id_conexao[3], self.id_conexao[1], self.servidor_seq_no, self.expected_seq_no, FLAGS_ACK)
                    self.servidor.rede.enviar(fix_checksum(header, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])

    def registrar_recebedor(self, callback):
        self.callback = callback

    def _try_send(self):
        bytes_em_transito = sum(len(s) - 4*(read_header(s)[4]>>12) for _, s in self.unacked_segments)

        while len(self.send_buffer) > 0 and bytes_em_transito < self.cwnd:
            chunk = self.send_buffer[:MSS]
            
            dest_addr, src_port, _, dest_port = self.id_conexao
            header = make_header(dest_port, src_port, self.servidor_seq_no, self.expected_seq_no, FLAGS_ACK)
            segmento_com_checksum = fix_checksum(header + chunk, self.id_conexao[2], dest_addr)

            self.send_times[self.servidor_seq_no] = time.time()
            self.unacked_segments.append((self.servidor_seq_no, segmento_com_checksum))
            
            if self.timer is None:
                self._iniciar_timer()

            self.servidor.rede.enviar(segmento_com_checksum, dest_addr)
            
            self.servidor_seq_no += len(chunk)
            self.send_buffer = self.send_buffer[MSS:]
            bytes_em_transito += len(chunk)

    def enviar(self, dados):
        if self.state != 'ESTABLISHED' or not dados: return
        self.send_buffer += dados
        self._try_send()

    def fechar(self):
        if self.state in ['LAST_ACK', 'CLOSED', 'FIN_WAIT_1']: return
        if self.state == 'CLOSE_WAIT': self.state = 'LAST_ACK'
        elif self.state == 'ESTABLISHED': self.state = 'FIN_WAIT_1'

        dest_addr, src_port, _, dest_port = self.id_conexao
        header = make_header(dest_port, src_port, self.servidor_seq_no, self.expected_seq_no, FLAGS_FIN | FLAGS_ACK)
        segmento_fin = fix_checksum(header, self.id_conexao[2], dest_addr)
        
        self.send_times[self.servidor_seq_no] = time.time()
        self.unacked_segments.append((self.servidor_seq_no, segmento_fin))
        if self.timer is None:
            self._iniciar_timer()
        
        self.servidor.rede.enviar(segmento_fin, dest_addr)
        self.servidor_seq_no += 1