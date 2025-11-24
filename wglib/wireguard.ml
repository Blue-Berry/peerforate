open Ctypes

type wg_key

let wg_key = ptr uchar

type wg_device_flags

module TimeSpec64 = struct
  (*   struct timespec64 { *)
  (* 	int64_t tv_sec; *)
  (* 	int64_t tv_nsec; *)
  (*   }; *)
  type timespec64

  let timespec64 : timespec64 structure typ = structure "timespec64"
  let tv_sec = field timespec64 "tv_sec" int64_t
  let tv_nsec = field timespec64 "tv_nsec" int64_t
  let () = seal timespec64
end

module Wg_endpoint = struct
  (* typedef union wg_endpoint { *)
  (* 	struct sockaddr addr; *)
  (* 	struct sockaddr_in addr4; *)
  (* 	struct sockaddr_in6 addr6; *)
  (* } wg_endpoint; *)
  type wg_endpoint

  let wg_endpoint : wg_endpoint union typ = union "wg_endpoint"
  let addr = field wg_endpoint "addr" Socket.Sockaddr.sockaddr
  let addr4 = field wg_endpoint "addr4" Socket.Sockaddr_in.sockaddr_in
  let addr6 = field wg_endpoint "addr6" Socket.Sockaddr_in6.sockaddr_in6
  let () = seal wg_endpoint
end

module Wg_peer = struct
  module AllowedIp = struct
    (*     typedef struct wg_allowedip { *)
    (* 	uint16_t family; *)
    (* 	union { *)
    (* 		struct in_addr ip4; *)
    (* 		struct in6_addr ip6; *)
    (* 	}; *)
    (* 	uint8_t cidr; *)
    (* 	struct wg_allowedip *next_allowedip; *)
    (* } wg_allowedip; *)

    type in_addr

    let in_addr : in_addr structure typ = structure "in_addr"
    let s_addr = field in_addr "s_addr" uint32_t
    let () = seal in_addr

    type in6_addr

    let in6_addr : in6_addr structure typ = structure "in6_addr"
    let s6_addr = Array.init 16 (fun _ -> field in6_addr "s6_addr" uchar)
    let () = seal in6_addr

    type ip_union

    let ip_union : ip_union union typ = union "ip_union"
    let ip4 = field ip_union "ip4" in_addr
    let ip6 = field ip_union "ip6" in6_addr
    let () = seal ip_union

    type wg_allowedip

    let wg_allowedip : wg_allowedip structure typ = structure "wg_allowedip"

    (* Define the wg_allowedip struct *)
    let family = field wg_allowedip "family" uint16_t
    let ip = field wg_allowedip "ip" ip_union
    let cidr = field wg_allowedip "cidr" uint8_t
    let next_allowedip = field wg_allowedip "next_allowedip" (ptr_opt wg_allowedip)
    let () = seal wg_allowedip
  end

  (* typedef struct wg_peer { *)
  (* 	enum wg_peer_flags flags; *)
  (* 	wg_key public_key; *)
  (* 	wg_key preshared_key; *)
  (* 	wg_endpoint endpoint; *)
  (* 	struct timespec64 last_handshake_time; *)
  (* 	uint64_t rx_bytes, tx_bytes; *)
  (* 	uint16_t persistent_keepalive_interval; *)
  (* 	struct wg_allowedip *first_allowedip, *last_allowedip; *)
  (* 	struct wg_peer *next_peer; *)
  (* } wg_peer; *)
  type wg_peer

  let wg_peer : wg_peer structure typ = structure "wg_peer"
  let flags = field wg_peer "flags" uint32_t
  let public_key = Array.init 32 (fun _ -> field wg_peer "public_key" uchar)
  let preshared_key = Array.init 32 (fun _ -> field wg_peer "preshared_key" uchar)
  let endpoint = field wg_peer "endpoint" Wg_endpoint.wg_endpoint
  let last_handshake_time = field wg_peer "last_handshake_time" TimeSpec64.timespec64
  let rx_bytes = field wg_peer "rx_bytes" uint64_t
  let tx_bytes = field wg_peer "tx_bytes" uint64_t

  let persistent_keepalive_interval =
    field wg_peer "persistent_keepalive_interval" uint16_t
  ;;

  let first_allowedip = field wg_peer "first_allowedip" (ptr_opt AllowedIp.wg_allowedip)
  let last_allowedip = field wg_peer "last_allowedip" (ptr_opt AllowedIp.wg_allowedip)
  let next_peer = field wg_peer "next_peer" (ptr_opt wg_peer)
  let () = seal wg_peer

  (* enum wg_peer_flags { *)
  (* 	WGPEER_REMOVE_ME = 1U << 0, *)
  (* 	WGPEER_REPLACE_ALLOWEDIPS = 1U << 1, *)
  (* 	WGPEER_HAS_PUBLIC_KEY = 1U << 2, *)
  (* 	WGPEER_HAS_PRESHARED_KEY = 1U << 3, *)
  (* 	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4 *)
  (* }; *)
  module Wg_peer_flags = struct
    let wgpeer_remove_me = 1 lsl 0
    let wgpeer_replace_allowedips = 1 lsl 1
    let wgpeer_has_public_key = 1 lsl 2
    let wgpeer_has_preshared_key = 1 lsl 3
    let wgpeer_has_persistent_keepalive_interval = 1 lsl 4
  end
end

module Wg_device = struct
  (* typedef struct wg_device { *)
  (* 	char name[IFNAMSIZ]; *)
  (* 	uint32_t ifindex; *)

  (* enum wg_device_flags flags; *)

  (* wg_key public_key; *)
  (* wg_key private_key; *)

  (* uint32_t fwmark; *)
  (* uint16_t listen_port; *)

  (* 	struct wg_peer *first_peer, *last_peer; *)
  (* } wg_device; *)

  type wg_device

  let wg_device : wg_device structure typ = structure "wg_device"
  let name = Array.init 16 (fun _ -> field wg_device "name" char)
  let ifindex = field wg_device "ifindex" uint32_t
  let flags = field wg_device "flags" uint32_t

  (* let public_key = field wg_device "public_key" wg_key *)
  let public_key = Array.init 32 (fun _ -> field wg_device "public_key" uchar)

  (* let private_key = field wg_device "private_key" wg_key *)
  let private_key = Array.init 32 (fun _ -> field wg_device "private_key" uchar)
  let fwmark = field wg_device "fwmark" uint32_t
  let listen_port = field wg_device "listen_port" uint16_t
  let first_peer = field wg_device "first_peer" (ptr_opt Wg_peer.wg_peer)
  let last_peer = field wg_device "last_peer" (ptr_opt Wg_peer.wg_peer)
  let () = seal wg_device

  (** enum wg_device_flags {
     WGDEVICE_REPLACE_PEERS = 1U << 0,
     WGDEVICE_HAS_PRIVATE_KEY = 1U << 1,
     WGDEVICE_HAS_PUBLIC_KEY = 1U << 2,
     WGDEVICE_HAS_LISTEN_PORT = 1U << 3,
     WGDEVICE_HAS_FWMARK = 1U << 4} **)
  module Wg_device_flags = struct
    let wgdevice_replace_peers = 1 lsl 0
    let wgdevice_has_private_key = 1 lsl 1
    let wgdevice_has_public_key = 1 lsl 2
    let wgdevice_has_listen_port = 1 lsl 3
    let wgdevice_has_fwmark = 1 lsl 4
  end
end

open Foreign
open Wg_device

(* int wg_set_device(wg_device *dev); *)
let wg_set_device = foreign "wg_set_device" (ptr wg_device @-> returning int)

let wg_get_device =
  foreign "wg_get_device" (ptr (ptr wg_device) @-> string @-> returning int)
;;

let wg_add_device = foreign "wg_add_device" (string @-> returning int)
let wg_del_device = foreign "wg_del_device" (string @-> returning int)
let wg_free_device = foreign "wg_free_device" (wg_device @-> returning void)
let wg_list_device_names = foreign "wg_list_device_names" (void @-> returning string)

(* void wg_key_to_base64(wg_key_b64_string base64, const wg_key key); *)
(* int wg_key_from_base64(wg_key key, const wg_key_b64_string base64); *)
(* bool wg_key_is_zero(const wg_key key); *)

let wg_generate_public_key =
  foreign
    "wg_generate_public_key"
    (wg_key @-> Ctypes_static.const wg_key @-> returning void)
;;

let wg_generate_private_key = foreign "wg_generate_private_key" (wg_key @-> returning void)

let wg_generate_preshared_key =
  foreign "wg_generate_preshared_key" (wg_key @-> returning void)
;;

(* void wg_key_to_base64(wg_key_b64_string base64, const wg_key key); *)
let wg_key_to_base64 =
  foreign "wg_key_to_base64" (ptr Ctypes.char @-> Ctypes.const wg_key @-> returning void)
;;

(* int wg_key_from_base64(wg_key key, const wg_key_b64_string base64); *)
let wg_key_from_base64 =
  foreign "wg_key_from_base64" (wg_key @-> ptr Ctypes.char @-> returning int)
;;

let wg_device_new = foreign "wg_device_new" (void @-> returning (ptr wg_device))
