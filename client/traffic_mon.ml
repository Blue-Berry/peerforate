open Core
module Wg = Wglib.Wgapi

module Allowed_ip_map = struct
  type key = Ipaddr.Prefix.t
  type t = (Ipaddr.Prefix.t * Wg.Key.t) list

  let of_interface (wg_int : Wg.Interface.t) =
    let peers =
      wg_int.peers
      |> List.filter ~f:(fun p ->
        (not @@ List.is_empty p.allowed_ips) && Option.is_some p.public_key)
    in
    let a_ips, peers =
      List.fold ~init:([], []) peers ~f:(fun (a_ips, peers) p ->
        ( List.append p.allowed_ips a_ips
        , List.append
            (List.init ~f:(fun _ -> Option.value_exn p.public_key) (List.length a_ips))
            peers ))
    in
    let ip_peers : t = List.zip_exn a_ips peers in
    ip_peers
  ;;

  let find (t : t) (ip : Ipaddr.t) =
    List.find_map t ~f:(fun (prefix, key) ->
      if Ipaddr.Prefix.mem ip prefix then Some key else None)
  ;;

  let keys t = List.unzip t |> fst
end

(* TODO: Handle exceptions *)
let start ~sw (wg_int : Wg.Interface.t) =
  let map = Allowed_ip_map.of_interface wg_int in
  let callback : Traffic_hook.callback =
    fun ~(dst_ip : Ipaddr.t) ~(timestamp : int64) ->
    match Allowed_ip_map.find map dst_ip with
    | None -> ()
    | Some key ->
      Eio.traceln
        "Packet dest: %s; For Peer: %s; ts: %s"
        (Ipaddr.to_string dst_ip)
        (Wg.Key.to_base64_string key)
        (Int64.to_string timestamp)
  in
  Traffic_hook.start_eio
    ~sw
    ~interface:wg_int.name
    ~target_subnets:(Allowed_ip_map.keys map)
    ~debounce_ms:3000
    callback
;;
