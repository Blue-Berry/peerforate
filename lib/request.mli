module Packet : sig
  type t

  val sizeof_t : int
  val payload_size : int
  val get_t_version : t -> int
  val get_t_timestamp : t -> int64
  val copy_t_mac : t -> string
  val copy_t_hst_key : t -> string
  val copy_t_dest_key : t -> string
  val hexdump_t_to_buffer : Buffer.t -> t -> unit
  val hexdump_t : t -> unit
  val sexp_of_t : t -> Sexplib.Sexp.t
  val t_of_sexp : Sexplib.Sexp.t -> t
  val of_bytes : ?hdr:bool -> bytes -> t
  val create_buffer : ?hdr:bool -> unit -> bytes

  val gen_mac
    :  priv_key:Mirage_crypto_ec.X25519.secret
    -> pub_key:string
    -> hst_key:string
    -> dest_key:string
    -> int64
    -> string

  val create
    :  source:int
    -> dest_port:int
    -> hst_key:Wglib.Wgapi.Key.t
    -> dest_key:Wglib.Wgapi.Key.t
    -> priv_key:Mirage_crypto_ec.X25519.secret
    -> pub_key:string
    -> t
end

module RawUdpSock : sig
  type t = Unix.file_descr

  val init : unit -> t
  val send : t -> Packet.t -> dest:Unix.sockaddr -> int
end
