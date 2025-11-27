type t
type 'a io = 'a
type stack
type io_addr = Ipaddr.t * int
type context

val nameservers : t -> Dns.proto * io_addr list

val getaddrinfo
  :  t
  -> 'response Dns.Rr_map.rr
  -> 'a Domain_name.t
  -> ('response, [> `Msg of string ]) result io

val gethostbyname
  :  t
  -> [ `host ] Domain_name.t
  -> (Ipaddr.V4.t, [> `Msg of string ]) result io

val gethostbyname6
  :  t
  -> [ `host ] Domain_name.t
  -> (Ipaddr.V6.t, [> `Msg of string ]) result io

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
       io

val get_raw_reply
  :  t
  -> 'response Dns.Rr_map.rr
  -> 'a Domain_name.t
  -> (Dns.Packet.reply, [> `Msg of string | `Partial ]) result io

val create
  :  ?nameservers:Dns.proto * io_addr list
  -> clock:float Eio.Time.clock_ty Eio.Resource.t
  -> timeout:int64
  -> sw:Eio.Switch.t
  -> net:Eio_unix.Net.t
  -> unit
  -> t
