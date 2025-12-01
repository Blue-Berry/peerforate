type client =
  { endpoint : Ipaddr.t
  ; port : int
  ; last_seen : Core.Time_float.t
  }

type t = (string, client) Core.Hashtbl.t

val create : unit -> t
val update : t -> string Core.Hashtbl.key -> client -> unit
val get : t -> string -> client option

module Req = Wg_nat.Request.Packet
module Rep = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

val handle_packet
  :  t
  -> Req.t
  -> client_addr:Ipaddr.t
  -> client_port:int
  -> (Ipaddr.t * int) option
