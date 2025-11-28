open Core

external apply_nat_punch_filter
  :  int
  -> int32
  -> int
  -> int
  -> int
  = "caml_apply_nat_punch_filter"

let attach_filter ~(sock : Core_unix.File_descr.t) ~server_ip ~server_port ~wg_port =
  let server_ip = Core_unix.Inet_addr.inet4_addr_to_int32_exn server_ip in
  let sock_fd = Core_unix.File_descr.to_int sock in
  let result = apply_nat_punch_filter sock_fd server_ip server_port wg_port in
  if result <> 0
  then
    failwith
      (Printf.sprintf
         "Failed to attach BPF filter (errno %d): %s"
         (-result)
         (Core_unix.Error.message (Core_unix.Error.of_system_int ~errno:(-result))))
;;
