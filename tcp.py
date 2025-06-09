import asyncio
from grader.tcputils import *
import random


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes.get(id_conexao)
            if conexao is None:
                servidor_seq_no = random.randint(0, 0xffff)
                conexao = Conexao(self, id_conexao, seq_no, servidor_seq_no)
                self.conexoes[id_conexao] = conexao
                
                # Envio do SYN+ACK com checksum corrigido
                header = make_header(dst_port, src_port, conexao.servidor_seq_no, seq_no + 1, FLAGS_SYN | FLAGS_ACK)
                segmento_syn_ack = fix_checksum(header, dst_addr, src_addr)
                
                # Armazena o segmento completo para retransmissão e inicia o timer
                conexao.unacked_segments.append((conexao.servidor_seq_no, segmento_syn_ack))
                conexao._iniciar_timer()
                self.rede.enviar(segmento_syn_ack, src_addr)
                conexao.servidor_seq_no += 1
                
                if self.callback:
                    self.callback(conexao)

        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, servidor_seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        # --- Variáveis de estado ---
        self.servidor_seq_no = servidor_seq_no 
        self.expected_seq_no = seq_no + 1      
        self.unacked_segments = []             
        self.timer = None                      
        self.timeout_interval = 1
        self.state = 'ESTABLISHED' # Adiciona estado da conexão

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

        # Pega o segmento mais antigo (o primeiro da lista) para reenviar
        _seq, segment_to_resend = self.unacked_segments[0]
        dest_addr = self.id_conexao[0]
        
        self.servidor.rede.enviar(segment_to_resend, dest_addr)
        print("Timeout! Reenviando segmento...")
        
        # Reinicia o timer
        self._iniciar_timer()


    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # Se a conexão já foi completamente fechada, ignora qualquer pacote
        if self.state == 'CLOSED':
            return

        # 1. Processa o campo ACK
        if (flags & FLAGS_ACK):
            # Se estamos em LAST_ACK, este ACK é o que fecha a conexão
            if self.state == 'LAST_ACK' and ack_no == self.servidor_seq_no:
                self.state = 'CLOSED'
                self._cancelar_timer()
                self.unacked_segments = []
                return

            # Limpa segmentos que foram confirmados
            acked_count = 0
            for unacked_seq, segment in self.unacked_segments:
                header_len = 4 * (read_header(segment)[4] >> 12)
                data_len = len(segment) - header_len
                if data_len == 0 and (read_header(segment)[4] & (FLAGS_SYN | FLAGS_FIN)):
                    data_len = 1
                
                if unacked_seq + data_len <= ack_no:
                    acked_count += 1
                else:
                    break
            
            if acked_count > 0:
                self.unacked_segments = self.unacked_segments[acked_count:]
                self._cancelar_timer()
                if self.unacked_segments:
                    self._iniciar_timer()

        # 2. Processa os dados e/ou FIN recebidos, se estiverem na ordem correta
        # e a conexão não estiver já fechada ou esperando o último ACK.
        if self.state in ['ESTABLISHED', 'CLOSE_WAIT']:
            should_send_ack = False
            if seq_no == self.expected_seq_no:
                if len(payload) > 0:
                    self.expected_seq_no += len(payload)
                    if self.callback: self.callback(self, payload)
                    should_send_ack = True

                if (flags & FLAGS_FIN):
                    # Cliente iniciou o fechamento. Entramos em CLOSE_WAIT.
                    self.state = 'CLOSE_WAIT'
                    self.expected_seq_no += 1
                    if self.callback: self.callback(self, b'')
                    should_send_ack = True
            
            # 3. Envia um ACK de volta se dados ou FIN em ordem foram recebidos
            if should_send_ack:
                header = make_header(self.id_conexao[3], self.id_conexao[1], self.servidor_seq_no, self.expected_seq_no, FLAGS_ACK)
                self.servidor.rede.enviar(fix_checksum(header, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0])


    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        # Não permite enviar dados se a conexão estiver sendo fechada ou já fechada.
        if self.state != 'ESTABLISHED':
            return
        if not dados: return
        dest_addr, src_port, _, dest_port = self.id_conexao

        while len(dados) > 0:
            chunk = dados[:MSS]
            
            header = make_header(dest_port, src_port, self.servidor_seq_no, self.expected_seq_no, FLAGS_ACK)
            segmento_com_checksum = fix_checksum(header + chunk, self.id_conexao[2], dest_addr)

            self.unacked_segments.append((self.servidor_seq_no, segmento_com_checksum))
            
            if self.timer is None:
                self._iniciar_timer()

            self.servidor.rede.enviar(segmento_com_checksum, dest_addr)
            self.servidor_seq_no += len(chunk)
            dados = dados[MSS:]

    def fechar(self):
        # Não faz nada se já estivermos no processo de fechar
        if self.state in ['LAST_ACK', 'CLOSED', 'FIN_WAIT_1']:
            return

        if self.state == 'CLOSE_WAIT':
            self.state = 'LAST_ACK'
        elif self.state == 'ESTABLISHED':
            self.state = 'FIN_WAIT_1' # Não coberto pelos testes, mas é o estado correto

        dest_addr, src_port, _, dest_port = self.id_conexao
        flags = FLAGS_FIN | FLAGS_ACK
        header = make_header(dest_port, src_port, self.servidor_seq_no, self.expected_seq_no, flags)
        segmento_fin = fix_checksum(header, self.id_conexao[2], dest_addr)
        
        self.unacked_segments.append((self.servidor_seq_no, segmento_fin))
        if self.timer is None:
            self._iniciar_timer()
        
        self.servidor.rede.enviar(segmento_fin, dest_addr)
        self.servidor_seq_no += 1