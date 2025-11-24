#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <linux/filter.h>
#include <stdint.h>
#include <sys/socket.h>

CAMLprim value caml_apply_nat_punch_filter(value v_sock_fd, value v_server_ip,
                                           value v_server_port,
                                           value v_wg_port) {
  CAMLparam4(v_sock_fd, v_server_ip, v_server_port, v_wg_port);

  int sock_fd = Int_val(v_sock_fd);
  uint32_t server_ip = Int32_val(v_server_ip);
  uint16_t server_port = Int_val(v_server_port);
  uint16_t wg_port = Int_val(v_wg_port);
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 12),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, server_ip, 0, 5),
      BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, server_port, 0, 3),
      BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 22),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, wg_port, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, -1),
      BPF_STMT(BPF_RET + BPF_K, 0)};

  struct sock_fprog prog = {.len = sizeof(filter) / sizeof(filter[0]),
                            .filter = filter};

  return setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
}
