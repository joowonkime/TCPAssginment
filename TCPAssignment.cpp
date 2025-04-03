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
  (void)syscallUUID;
  (void)pid;

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    break;
  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case CONNECT:
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
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
         return;
     }
    }
  }
  this->returnSystemCall(syscallUUID, 0);
  
}
void TCPAssignment::syscall_getsockname() {

}
void TCPAssignment::syscall_connect() {

}
void TCPAssignment::syscall_listen() {

}
void TCPAssignment::syscall_accept() {

}
void TCPAssignment::syscall_close() {

}
void TCPAssignment::syscall_read() {

}
void TCPAssignment::syscall_write() {

}
void TCPAssignment::syscall_getpeername() {

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
  serverSocket.state = SYN_RECEIVED;
  size_t flag_buffer;
  size_t client_isn;
  packet.readData(FLAGS, &flag_buffer, 1);
  packet.readData(SEQNUM, &client_isn, 4);
  uint8_t syn_flag = flag_buffer & 0x02;
  uint8_t ack_flag = flag_buffer & 0x10;
  if (syn_flag == 0x00 && ack_flag == 0x10) {
    Packet &&serverPacket = packet.clone();
    serverSocket.state = ESTABLISHED;
    clientSocket.state = ESTABLISHED;
    returnSystemCall(serverPacket.getUUID(), serverPacket.getUUID());
  }
  else if (syn_flag == 0x02) {
    serverSocket.state = SYN_RECEIVED;
    clientSocket.state = SYN_RECEIVED;
    size_t flag_buffer = 0x12;
    size_t seqNum = std::rand();
    size_t ackNum = client_isn + 1;
    Packet &&serverPacket = packet.clone();
    serverPacket.writeData(FLAGS, &flag_buffer, 1);
    serverPacket.writeData(SEQNUM, &seqNum, 4);
    serverPacket.writeData(ACKNUM, &ackNum, 4);
    sendPacket("IPv4", std::move(serverPacket));
}
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
