module State : sig
  type t

  val create : Dns_trie.t -> t
  val update : f:(Dns_server.Primary.s -> Dns_server.Primary.s) -> t -> unit

  (* val handle_request *)
  (*   :  t *)
  (*   -> now:Ptime.t *)
  (*   -> ts:int64 *)
  (*   -> proto:Dns.proto *)
  (*   -> src:Ipaddr.t *)
  (*   -> src_port:int *)
  (*   -> buf:string *)
  (*   -> string list *)
end

val build_trie : unit -> Dns_trie.t

val dns_serve
  :  net:[> [> `Generic ] Eio.Net.ty ] Eio.Resource.t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Resource.t
  -> State.t
  -> 'a

val record_populator : clock:[> float Eio.Time.clock_ty ] Eio.Resource.t -> State.t -> 'a
val add_record : State.t -> 'a Domain_name.t -> 'b Dns.Rr_map.rr -> 'b -> unit
