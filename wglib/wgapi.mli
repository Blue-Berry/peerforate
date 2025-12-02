val af_inet : int
val af_inet6 : int

module Key : sig
  type t

  val generate_private_key : unit -> t
  val generate_public_key : t -> t
  val generate_preshared_key : unit -> t
  val to_base64_string : t -> string
  val of_base64_string : string -> (t, string) result
  val to_string : t -> string
  val of_string : string -> t
  val sexp_of_t : t -> Base.Sexp.t
  val t_of_sexp : Base.Sexp.t -> t
end

module Allowed_ip : sig
  module Ip = Ipaddr

  type t =
    { ip : Ip.t
    ; cidr : Unsigned.uint8
    }
end

module Endpoint : sig
  type t =
    { addr : [ `V4 of Ipaddr.V4.t | `V6 of Ipaddr.V6.t ]
    ; port : int
    }
end

module Peer : sig
  type t =
    { public_key : Key.t option
    ; preshared_key : Key.t option
    ; endpoint : Endpoint.t option
    ; last_handshake_time : float
    ; rx_bytes : int
    ; tx_bytes : int
    ; persistent_keepalive_interval : int option
    ; allowed_ips : Allowed_ip.t list
    }

  val create
    :  ?public_key:Key.t
    -> ?preshared_key:Key.t
    -> ?endpoint:Endpoint.t
    -> ?persistent_keepalive_interval:int
    -> ?allowed_ips:Allowed_ip.t list
    -> unit
    -> t

  (* TODO: modify peer *)
end

module Interface : sig
  type t =
    { name : string
    ; ifindex : int
    ; public_key : Key.t option
    ; private_key : Key.t option
    ; fwmark : int option
    ; listen_port : int option
    ; peers : Peer.t list
    }

  val create
    :  name:string
    -> ?public_key:Key.t
    -> ?private_key:Key.t
    -> ?fwmark:int
    -> ?listen_port:int
    -> ?peers:Peer.t list
    -> unit
    -> t

  val to_wg_device
    :  t
    -> (Wireguard.Wg_device.wg_device, [ `Struct ]) Ctypes_static.structured

  val of_wg_device
    :  (Wireguard.Wg_device.wg_device, [ `Struct ]) Ctypes_static.structured
    -> t

  val get_device : string -> (t, string) result

  module DeviceError : sig
    type t =
      | EPERM
      | ENOENT
      | ESRCH
      | EINTR
      | EIO
      | ENXIO
      | E2BIG
      | ENOEXEC
      | EBADF
      | ECHILD
      | EAGAIN
      | ENOMEM
      | EACCES
      | EFAULT
      | ENOTBLK
      | EBUSY
      | EEXIST
      | EXDEV
      | ENODEV
      | ENOTDIR
      | EISDIR
      | EINVAL
      | ENFILE
      | EMFILE
      | ENOTTY
      | ETXTBSY
      | EFBIG
      | ENOSPC
      | ESPIPE
      | EROFS
      | EMLINK
      | EPIPE
      | EDOM
      | ERANGE

    val to_string : t -> string
    val of_int : int -> (unit, t) result
  end

  val set_device : t -> (unit, DeviceError.t) result
  val add_peers : t -> Peer.t list -> (unit, DeviceError.t) result
  val set_peers : t -> Peer.t list -> (unit, DeviceError.t) result
  val configure_peers : 'a -> 'b
  val remove_peers : t -> Peer.t list -> (unit, DeviceError.t) result
end
