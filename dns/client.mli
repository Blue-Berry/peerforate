module T : sig
  type 'a io = 'a

  type stack =
    { net : Eio_unix.Net.t
    ; sw : Eio.Switch.t
    ; clock : float Eio.Time.clock_ty Eio.Resource.t
    }

  type io_addr = Ipaddr.t * int

  type t =
    { net : Eio_unix.Net.t
    ; nameservers : Dns.proto * io_addr list
    ; timeout_ns : int64
    ; sw : Eio.Switch.t
    ; clock : float Eio.Time.clock_ty Eio.Resource.t
    }

  type context =
    { socket : [ `Generic ] Eio.Net.datagram_socket_ty Eio.Resource.t
    ; addr : Eio.Net.Sockaddr.datagram
    ; timeout_s : float
    ; clock : float Eio.Time.clock_ty Eio.Resource.t
    }

  val create : ?nameservers:Dns.proto * io_addr list -> timeout:int64 -> stack -> t
  val nameservers : t -> Dns.proto * io_addr list
  val rng : int -> string
  val clock : unit -> int64
  val connect : t -> (Dns.proto * context, [> `Msg of string ]) result
  val send_recv : context -> string -> (string, [> `Msg of string ]) result
  val close : 'a -> unit
  val bind : 'a -> ('a -> 'b) -> 'b
  val lift : 'a -> 'a
end

type 'a io = 'a

type stack = T.stack =
  { net : Eio_unix.Net.t
  ; sw : Eio.Switch.t
  ; clock : float Eio.Time.clock_ty Eio.Resource.t
  }

type io_addr = Ipaddr.t * int

type context = T.context =
  { socket : [ `Generic ] Eio.Net.datagram_socket_ty Eio.Resource.t
  ; addr : Eio.Net.Sockaddr.datagram
  ; timeout_s : float
  ; clock : float Eio.Time.clock_ty Eio.Resource.t
  }

type t = Dns_client.Make(T).t

val transport : t -> T.t

val create
  :  ?cache_size:int
  -> ?edns:[ `Auto | `Manual of Dns.Edns.t | `None ]
  -> ?nameservers:Dns.proto * T.io_addr list
  -> ?timeout:int64
  -> T.stack
  -> t

val nameservers : t -> Dns.proto * T.io_addr list

val getaddrinfo
  :  t
  -> 'response Dns.Rr_map.rr
  -> 'a Domain_name.t
  -> ('response, [> `Msg of string ]) result T.io

val gethostbyname
  :  t
  -> [ `host ] Domain_name.t
  -> (Ipaddr.V4.t, [> `Msg of string ]) result T.io

val gethostbyname6
  :  t
  -> [ `host ] Domain_name.t
  -> (Ipaddr.V6.t, [> `Msg of string ]) result T.io

val get_resource_record
  :  t
  -> 'response Dns.Rr_map.rr
  -> 'a Domain_name.t
  -> ( 'response
       , [> `Msg of string
         | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
         | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t
         ] )
       result
       T.io

val get_raw_reply
  :  t
  -> 'response Dns.Rr_map.rr
  -> 'a Domain_name.t
  -> (Dns.Packet.reply, [> `Msg of string | `Partial ]) result T.io

val create_client
  :  ?nameservers:Dns.proto * T.io_addr list
  -> clock:float Eio.Time.clock_ty Eio.Resource.t
  -> timeout:int64
  -> sw:Eio.Switch.t
  -> net:Eio_unix.Net.t
  -> unit
  -> t
