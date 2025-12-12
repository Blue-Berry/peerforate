open Core
module Wg = Wglib.Wgapi
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

module Allowed_ip_map = struct
  type t = (Ipaddr.Prefix.t * Wg.Key.t) list

  let to_sexp t =
    List.sexp_of_t
      (sexp_of_pair
         (fun x -> String.sexp_of_t @@ Ipaddr.Prefix.to_string x)
         (fun k -> Wg.Key.to_base64_string k |> String.sexp_of_t))
      t
  ;;

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
            (List.init
               ~f:(fun _ -> Option.value_exn p.public_key)
               (List.length p.allowed_ips))
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

let update_peer
      ~clock
      ~(wg_intrf : Wg.Interface.t)
      ~(conf : Config.t)
      ~server_key
      ~dst_key
  =
  let pub_key =
    wg_intrf.public_key |> Option.value_exn ~message:"Failed to get device public key"
  in
  let priv_key =
    wg_intrf.private_key |> Option.value_exn ~message:"Failed to get device private key"
  in
  let sock = Wg_nat.Request.RawUdpSock.init () in
  let listen_port =
    wg_intrf.listen_port |> Option.value_exn ~message:"Failed to get device listen port"
  in
  Bpf_filter.attach_filter
    ~sock
    ~server_ip:(Core_unix.Inet_addr.of_string conf.server_endpoint)
    ~server_port:conf.server_port
    ~wg_port:listen_port;
  let reply =
    Fetch_peer.fetch_peer_endpoint
      ~source_port:listen_port
      ~server_key
      ~hst_pub_key:pub_key
      ~hst_priv_key:priv_key
      ~dest_pub_key:dst_key
      ~sock
      ~clock
      conf
  in
  match reply with
  | Some reply ->
    let dest_addr =
      R.get_t_addr reply |> Option.value_exn ~message:"Failed to get reply addr"
    in
    let dest_port = R.get_t_port reply in
    Eio.traceln "Setting peer endpoint: %s:%d" (Ipaddr.to_string dest_addr) dest_port;
    Wgctrl.update_peer wg_intrf dst_key dest_addr dest_port
    |> (function
     | Ok () -> ()
     | Error err ->
       Logs.warn (fun m ->
         m
           "Failed to set wg interface: %s"
           (Wglib.Wgapi.Interface.DeviceError.to_string err)))
  | None -> Logs.info (fun m -> m "Invalid Response")
;;

let callback ~clock ~(wg_intrf : Wg.Interface.t) ~(conf : Config.t) ~server_key ~map =
  fun ~(dst_ip : Ipaddr.t) ~(timestamp : int64) ->
  Eio.traceln
    "%s: Traffic monitor callback. dest ip: %s"
    (Int64.to_string timestamp)
    (Ipaddr.to_string dst_ip);
  match Allowed_ip_map.find map dst_ip with
  | None -> ()
  | Some dst_key ->
    Eio.traceln
      "%s Updating Peer: %s"
      (Int64.to_string timestamp)
      (Wg.Key.to_base64_string dst_key);
    update_peer ~clock ~wg_intrf ~conf ~server_key ~dst_key
;;

(* TODO: Handle exceptions *)
let start ~sw ~clock ~(wg_intrf : Wg.Interface.t) ~conf ~server_key =
  let map = Allowed_ip_map.of_interface wg_intrf in
  Eio.traceln
    "Starting traffic monitor : %s"
    (Allowed_ip_map.to_sexp map |> Sexp.to_string_hum);
  let callback : Traffic_hook.callback =
    callback ~clock ~wg_intrf ~conf ~server_key ~map
  in
  Traffic_hook.start_eio
    ~sw
    ~interface:wg_intrf.name
    ~target_subnets:(Allowed_ip_map.keys map)
    ~debounce_ms:3000
    callback
;;
