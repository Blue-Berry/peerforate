open Core
module M = Hashtbl.Make (String)
module Wg = Wglib.Wgapi

let start ~_sw (wg_int : Wg.Interface.t) =
  let _peers =
    wg_int.peers |> List.filter ~f:(fun p -> not @@ List.is_empty p.allowed_ips)
  in
  ()
;;
