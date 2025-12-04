open Core
module M = Hashtbl.Make (String)

type client =
  { endpoint : Ipaddr.t
  ; port : int
  ; last_seen : Time_float.t
  }

type t = (string, client) M.hashtbl

let create () : t =
  let t = M.create () in
  let c : client =
    { endpoint = Ipaddr.of_string_exn "127.0.0.1"
    ; port = 5280
    ; last_seen = Time_float.now ()
    }
  in
  Hashtbl.set
    t
    ~key:
      (Wglib.Wgapi.Key.of_base64_string "MYaTPEhxXQANDdHW9lPdJ4D4Yrbrk4PPP/v9X6BQ+hc="
       |> Stdlib.Result.get_ok
       |> Wglib.Wgapi.Key.to_string)
    ~data:c;
  t
;;

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
  Hashtbl.find t dest_key
  |> Option.bind ~f:(fun c ->
    let age = Time_float.(abs_diff (now ()) c.last_seen) in
    if Time_float.Span.(of_int_min 20 < age) then None else Some (c.endpoint, c.port))
;;

(* TODO: *)
let cleanup (t : t) max_age =
  let now_f = Time_float.now () in
  Hashtbl.filter_inplace t ~f:(fun c ->
    let age = Time_float.(abs_diff now_f c.last_seen) in
    Time_float.Span.(age < max_age))
;;
