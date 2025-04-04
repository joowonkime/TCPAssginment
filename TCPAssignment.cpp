/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  next_fd = 3;

}

void TCPAssignment::finalize() {
  socketTable.clear();
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter &param) {

  // Remove below

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
                       std::get<void *>(param.params[1]),
                       std::get<int>(param.params[2]));
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<void *>(param.params[1]),
                        std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol) {
  
  TCPSocket newSocket;

  newSocket.fd = next_fd++;
  newSocket.domain = domain;
  newSocket.type = type;
  newSocket.protocol = protocol;
  newSocket.state = CLOSED;
  std::memset(&newSocket.localAddr, 0, sizeof(newSocket.localAddr));
  std::memset(&newSocket.remoteAddr, 0, sizeof(newSocket.remoteAddr));
  newSocket.backlog = 0;
  socketTable[newSocket.fd] = newSocket;
  this->returnSystemCall(syscallUUID, newSocket.fd);

}
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  if(addrlen < sizeof(struct sockaddr_in)){
    this -> returnSystemCall(syscallUUID, -1);
  }

  if(addr.sin_family != AF_INET){
    this -> returnSystemCall(syscallUUID, -1);
  }

  for(auto &socket : sockTable){
    if(sockTable.first == sockfd){
      TCPSocket &newsocket = sockTable.second;
    }
  }
  newsocket.localAddr = *( (struct sockaddr_in*) addr );

  uint16_t bindPort = newsocket.localAddr.sin_port;
  uint32_t effectiveIP = newsocket.localAddr.sin_addr.s_addr;

  for(auto &entry sockTable){
    // 자기 자신은 건너뜀
    if (entry.first == sockfd)
      continue;
    // 닫힌 소켓은 체크하지 않음
    if (entry.second.state == CLOSED)
      continue;
    // 포트 번호가 같은 경우
    if (entry.second.localAddr.sin_port == bindPort) {
     // 아래 세 경우 중 하나라도 만족하면 중복으로 간주:
     // - 기존 소켓의 IP가 INADDR_ANY
     // - 새로 바인딩할 IP가 INADDR_ANY
     // - 두 IP가 동일한 경우
     if (entry.second.localAddr.sin_addr.s_addr == INADDR_ANY || effectiveIP == INADDR_ANY ||
         entry.second.localAddr.sin_addr.s_addr == effectiveIP) {
         this->returnSystemCall(syscallUUID, -1);
     }
    }
  }
  this->returnSystemCall(syscallUUID, 0);
  
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (addrlen == nullptr || *addrlen < sizeof(struct sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
  }

  for (auto &socket : socketTable) {
    if (socket.first == sockfd) {
      std::memcpy(addr, &socket.second.localAddr, sizeof(struct sockaddr_in));
      *addrlen = sizeof(struct sockaddr_in);
      this->returnSystemCall(syscallUUID, 0);
    }
  }
  this->returnSystemCall(syscallUUID, -1);

}

//////######
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  if (addr == nullptr || addrlen < sizeof(struct sockaddr_in)) {
      this->returnSystemCall(syscallUUID, -1);
      return;
  }
  struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in*>(addr);
  if (addr_in->sin_family != AF_INET) {
      this->returnSystemCall(syscallUUID, -1);
      return;
  }
  auto it = socketTable.find(sockfd);
  if (it == socketTable.end()) {
      this->returnSystemCall(syscallUUID, -1);
      return;
  }
  
  TCPSocket &clientSocket = it->second;

  if (clientSocket.state != CLOSED) {
      this->returnSystemCall(syscallUUID, -1);
      return;
  }

  clientSocket.remoteAddr = *addr_in;
  clientSocket.state = SYN_SENT;

  Packet synPacket;
  uint8_t flag = 0x02; // SYN
  synPacket.writeData(FLAGS, &flag, 1);

  sendPacket("IPv4", std::move(synPacket));

  TimerPayload timerPayload { clientSocket.sockfd, syscallUUID, 0 };
  this->addTimer(std::any(timerPayload), 30000000000LL);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
  for (auto &socket : socketTable) {
    if (socket.first == sockfd) {
      TCPSocket &serverSocket = socket.second;
      serverSocket.state = LISTEN;
      serverSocket.backlog = backlog;

      this->returnSystemCall(syscallUUID, 0);
    }
  }
  this->returnSystemCall(syscallUUID, -1);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (addrlen == nullptr || *addrlen < sizeof(struct sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
  }

  for (auto &socket : socketTable) {
    if (socket.first == sockfd && socket.second.state == LISTEN) {
      TCPSocket &serverSocket = socket.second;
      TCPSocket newSocket;
      newSocket.fd = next_fd++;
      newSocket.domain = serverSocket.domain;
      newSocket.type = serverSocket.type;
      newSocket.protocol = serverSocket.protocol;
      newSocket.localAddr = serverSocket.localAddr;
      newSocket.remoteAddr = *(struct sockaddr_in *)addr;
      newSocket.state = ESTABLISHED;

      socketTable[newSocket.fd] = newSocket;

      std::memcpy(addr, &newSocket.remoteAddr, sizeof(struct sockaddr_in));
      *addrlen = sizeof(struct sockaddr_in);

      this->returnSystemCall(syscallUUID, newSocket.fd);
    }
  }
  this->returnSystemCall(syscallUUID, -1);

}
///####
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd) {
  for (auto &socket : socketTable) {
    if (socket.first == sockfd) {
      TCPSocket &socket = socket.second;
      if (socket.state == CLOSE_WAIT) {
        // Send FIN packet
        Packet finPacket;
        uint8_t flag = 0x01; // FIN 플래그
        finPacket.writeData(FLAGS, &flag, 1);
        // 여기서 추가적인 TCP 헤더 필드(예: SEQNUM)를 작성할 수 있음.
        sendPacket("IPv4", std::move(finPacket));
        socket.state = LAST_ACK;
        // 시스템 호출 결과 반환
        this->returnSystemCall(syscallUUID, 0);
        return;
      } 
      else if(socket.state == ESTABLISHED) {
        
      }
      
      else if (socket.state == LISTEN) {
        socket.state = CLOSED;
        this->returnSystemCall(syscallUUID, 0);
        return;
      }
    }
  }
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t len) {
  if (len == 0) {
    this->returnSystemCall(syscallUUID, -1);
  }

  for (auto &socket : socketTable) {
    if (socket.first == sockfd && socket.second.state == ESTABLISHED) {
      // Read data from the socket
      // This is a placeholder; actual implementation would involve reading from the socket buffer
      std::memset(buf, 0, len);
      this->returnSystemCall(syscallUUID, len);
    }
  }
  this->returnSystemCall(syscallUUID, -1);

}
void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t len) {
  if (len == 0) {
    this->returnSystemCall(syscallUUID, -1);
  }

  for (auto &socket : socketTable) {
    if (socket.first == sockfd && socket.second.state == ESTABLISHED) {
      // Write data to the socket
      // This is a placeholder; actual implementation would involve writing to the socket buffer
      this->returnSystemCall(syscallUUID, len);
    }
  }
  this->returnSystemCall(syscallUUID, -1);

}
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (addrlen == nullptr || *addrlen < sizeof(struct sockaddr_in)) {
    this->returnSystemCall(syscallUUID, -1);
  }

  for (auto &socket : socketTable) {
    if (socket.first == sockfd) {
      std::memcpy(addr, &socket.second.remoteAddr, sizeof(struct sockaddr_in));
      *addrlen = sizeof(struct sockaddr_in);
      this->returnSystemCall(syscallUUID, 0);
    }
  }
  this->returnSystemCall(syscallUUID, -1);
}



void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  int headerSize;
  int * databuff;
  packet.readData(12, &headerSize, 4);
  packet.readData(headerSize, databuff, packet.getSize() - headerSize);
  UUID syscall_ID = packet.getUUID();
  
  uint16_t sourcePort, destPort;
  TCPSocket serverSocket;
  TCPSocket clientSocket;
  struct sockaddr_in sourceAddr, destAddr;
  packet.readData(SOURCE_PORT, &sourcePort, 2);
  packet.readData(DEST_PORT, &destPort, 2);
  
  for ( auto &socket : socketTable) {
    if (socket.second.localAddr.sin_port == destPort && socket.second.remoteAddr.sin_port == destPort) {
      destAddr = socket.second.remoteAddr;
      clientSocket = socket.second;
      break;
    }
  }
  for ( auto &socket : socketTable) {
    if (socket.second.localAddr.sin_port == sourcePort && socket.second.remoteAddr.sin_port == sourcePort) {
      sourceAddr = socket.second.remoteAddr;
      serverSocket = socket.second; 
      break;
    }
  }

  if(serverSocket.state == ESTABLISHED && clientSocket.state == FIN_WAIT_1) { // close case
    size_t flag_buffer;
    packet.readData(FLAGS, &flag_buffer, 1);
    uint8_t fin_flag = flag_buffer & 0x01;
    // fin 0x01, ack 0x10
    if (fin_flag == 0x01) {
      serverSocket.state = CLOSE_WAIT;
      Packet &&serverPacket = packet.clone();
      serverPacket.writeData(FLAGS, &flag_buffer, 0x10); // ACK
      sendPacket("IPv4", std::move(serverPacket));
      this->returnSystemCall(serverPacket.getUUID(), serverPacket.getUUID());
    }
    else{
      this->returnSystemCall(serverPacket.getUUID(), -1);
    }
  }
  else if(serverSocket.state == CLOSE_WAIT && clientSocket.state == FIN_WAIT_1) {
    size_t flag_buffer;
    packet.readData(FLAGS, &flag_buffer, 1);
    uint8_t ack_flag = flag_buffer & 0x10;
    if (ack_flag == 0x10) {
      clientSocket.state = FIN_WAIT_2;
      serverSocket.state = LAST_ACK;
      Packet &&serverPacket = packet.clone();
      serverPacket.writeData(FLAGS, &flag_buffer, 0x01); // FIN
      sendPacket("IPv4", std::move(serverPacket));
      this->returnSystemCall(serverPacket.getUUID(), serverPacket.getUUID());
    }
    else{
      this->returnSystemCall(serverPacket.getUUID(), -1);
    }
  else if(serverSocket.state == LAST_ACK && clientSocket.state == FIN_WAIT_2) {
    size_t flag_buffer;
    packet.readData(FLAGS, &flag_buffer, 1);
    uint8_t fin_flag = flag_buffer & 0x01;
    if (fin_flag == 0x01) {
      clientSocket.state = TIME_WAIT;
      TimerPayload timerPayload {clientSocket.sockfd, syscallUUID, 0 };
      this->addTimer(std::any(timerPayload), 60000000000LL);
      Packet &&clientPacket = packet.clone();
      clientPacket.writeData(FLAGS, &flag_buffer, 0x10); // ACK
      sendPacket("IPv4", std::move(clientPacket));
      this->returnSystemCall(clientPacket.getUUID(), clientPacket.getUUID());
    }
    else{
      this->returnSystemCall(clientPacket.getUUID(), -1);
    }
  }
  else if(serverSocket.state == LAST_ACK && clientSocket.state == TIME_WAIT) {
    serverSocket.state = CLOSED;
    this->returnSystemCall(syscall_ID, 0);
  }
// 4way handshke end..

  else if(serverSocket.state == LISTEN && clientSocket.state == SYN_SENT){ // 3handshake case
    size_t flag_buffer;
    packet.readData(FLAGS, &flag_buffer, 1);
    uint8_t syn_flag = flag_buffer & 0x02;
    if(syn_flag == 0x02) {
      serverSocket.state = SYN_RECEIVED;
      size_t flag_buffer;
      size_t client_isn;
      packet.readData(FLAGS, &flag_buffer, 1);
      packet.readData(SEQNUM, &client_isn, 4);
      Packet &&serverPacket = packet.clone();
      serverPacket.writeData(FLAGS, &flag_buffer, 0x12); // SYN + ACK
      size_t server_isn = std::rand();
      serverPacket.writeData(SEQNUM, &server_isn, 4);
      size_t ack_num = client_isn + 1;
      serverPacket.writeData(ACKNUM, &ack_num, 4);
      TimerPayload timerPayload {clientSocket.sockfd, syscallUUID, 0 };
      addTimer(std::any(timerPayload), 30000000000LL);
      sendPacket("IPv4", std::move(serverPacket));

    }
    else {
      this->returnSystemCall(serverPacket.getUUID(), -1);
    }
    if (syn_flag == 0x00 && ack_flag == 0x10) {
      Packet &&serverPacket = packet.clone();
      serverSocket.state = ESTABLISHED;
      clientSocket.state = ESTABLISHED;
      this->returnSystemCall(serverPacket.getUUID(), serverPacket.getUUID());
    }
  }

  else if(serverSocket.state == SYN_SENT && clientSocket.state == SYN_RECEIVED) {
    size_t flag_buffer;
    packet.readData(FLAGS, &flag_buffer, 1);
    uint8_t ack_flag = flag_buffer & 0x10;
    if (ack_flag == 0x10) {
      cancelTimer(clientSocket.sockfd);
      serverSocket.state = ESTABLISHED;
      Packet &&clientPacket = packet.clone();
      clientPacket.writeData(FLAGS, & flag_buffer, 0x10); // ACK
      sendPacket("IPv4", std::move(clientPacket));
      this->returnSystemCall(clientPacket.getUUID(), clientPacket.getUUID());
    }
    else{
      this->returnSystemCall(clientPacket.getUUID(), -1);
    }
  }
  else if(serverSocket.state == ESTABLISHED && clientSocket.state == SYN_RECEIVED) {
    clientSocket.state = ESTABLISHED;
    this->returnSystemCall(clientPacket.getUUID(), 0);
  }
  
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  // case TIME_WAIT  or SYN_SENT or SYN_RECEIVED
  TimerPayload timerPayload = std::any_cast<TimerPayload>(payload);
  int sockfd = timerPayload.sockfd;

  auto it = socketTable.find(sockfd);
  if (it == socketTable.end()) {
    return;
  }
  TCPSocket &socket = it->second;
  if (socket.state == TIME_WAIT) {
    socket.state = CLOSED;
    this->returnSystemCall(timerPayload.syscallUUID, 0);
  } else if (socket.state == SYN_SENT) {
    socket.state = CLOSED;
    this->returnSystemCall(timerPayload.syscallUUID, -1);
  } else if (socket.state == SYN_RECEIVED) {
    socket.state = CLOSED;
    this->returnSystemCall(timerPayload.syscallUUID, -1);
  }
  else{
    this->returnSystemCall(timerPayload.syscallUUID, -1);
  }
}

} // namespace E
