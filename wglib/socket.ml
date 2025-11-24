open Ctypes

(* Define sockaddr structure *)
module Sockaddr = struct
  type sockaddr

  let sockaddr : sockaddr structure typ = structure "sockaddr"
  let sa_family = field sockaddr "sa_family" uint16_t

  (* let sa_data = field sockaddr "sa_data" (array 14 uint8_t) *)
  let sa_data = Array.init 14 (fun _ -> field sockaddr "sa_data" Ctypes.char)
  let () = seal sockaddr
end

(* Define sockaddr_in structure *)
module Sockaddr_in = struct
  type sockaddr_in

  let sockaddr_in : sockaddr_in structure typ = structure "sockaddr_in"
  let sin_family = field sockaddr_in "sin_family" uint16_t
  let sin_port = field sockaddr_in "sin_port" uint16_t

  (* let sin_addr = field sockaddr_in "sin_addr" (array 4 uint8_t) *)
  let sin_addr = field sockaddr_in "sin_addr" uint32_t
  let sin_zero = field sockaddr_in "sin_zero" (array 8 uint8_t)
  let () = seal sockaddr_in
end

(* Define sockaddr_in6 structure *)
module Sockaddr_in6 = struct
  type sockaddr_in6

  let sockaddr_in6 : sockaddr_in6 structure typ = structure "sockaddr_in6"
  let sin6_family = field sockaddr_in6 "sin6_family" uint16_t
  let sin6_port = field sockaddr_in6 "sin6_port" uint16_t
  let sin6_flowinfo = field sockaddr_in6 "sin6_flowinfo" uint32_t

  (* let sin6_addr = field sockaddr_in6 "sin6_addr" (array 16 uint8_t) *)
  let sin6_addr = Array.init 16 (fun _ -> field sockaddr_in6 "sin6_addr" uint8_t)
  let sin6_scope_id = field sockaddr_in6 "sin6_scope_id" uint32_t
  let () = seal sockaddr_in6
end
