/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

enum TCPState {
  CLOSED = 0,
  LISTEN = 1,
  SYN_SENT = 2,
  SYN_RECEIVED = 3,
  ESTABLISHED = 4
};


enum segmentStruct {
  SOURCE_PORT = 0,
  DEST_PORT = 2,
  SEQNUM = 4,
  ACKNUM = 8,
  HEADERLEN = 12,
  FLAGS = 13,
  RECEIVEDWINDOW = 14,
  CHECKSUM = 16,
  URGENTPOINTER = 18,
  OPTIONS = 20,
  PAYLOAD = 
}

struct TCPSocket {
  int fd;
  int domain;
  int type;
  int protocol;
  struct sockaddr_in localAddr;
  struct sockaddr_in remoteAddr;
  TCPState state;
  int backlog;
};

namespace E {

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

  // 내부 데이터: 파일 디스크립터와 소켓 정보를 저장하는 테이블
  std::map<int, TCPSocket> socketTable;
  // 파일 디스크립터 할당을 위한 변수 (예: 3부터 시작)
  int next_fd;

  // 시스템 콜 별 내부 구현 함수
  void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
  void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
  void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  void syscall_close(UUID syscallUUID, int pid, int sockfd);

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}


  

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
