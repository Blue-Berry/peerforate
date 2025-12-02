open Core
module M = Hashtbl.Make (String)

type client =
  { endpoint : Ipaddr.t
  ; port : int
  ; last_seen : Time_float.t
  }

type t = (string, client) M.hashtbl

let create () : t = M.create ()
let update (t : t) key c = Hashtbl.set t ~key ~data:c
let get t key = Hashtbl.find t key

module Req = Wg_nat.Request.Packet
module Rep = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

let handle_packet t (packet : Req.t) ~client_addr ~client_port =
  let hst_key = Req.copy_t_hst_key packet in
  let client : client =
    { endpoint = client_addr; port = client_port; last_seen = Time_float.now () }
  in
  update t hst_key client;
  let dest_key = Req.copy_t_dest_key packet in
  Hashtbl.find t dest_key |> Option.bind ~f:(fun c -> Some (c.endpoint, c.port))
;;

let cleanup (t : t) max_age =
  let now_f = Time_float.now () in
  Hashtbl.filter_inplace t ~f:(fun c ->
    let age = Time_float.(abs_diff now_f c.last_seen) in
    Time_float.Span.(age < max_age))
;;
