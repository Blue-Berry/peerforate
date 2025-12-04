open! Core
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

(* TODO: *)
(* - eBPF nat check when packet is being sent *)
(* Create a peer config system  *)

let get_config () =
  Config.read_config ()
  |> function
  | Some c -> c
  | None ->
    Config.init_config ~server_endpoint:"127.0.0.1" ~server_port:49918 ~wg_interface:"wg8"
;;

let get_key ~net ~clock (conf : Config.t) =
  let open Dnslib in
  Eio.Switch.run
  @@ fun sw ->
  let nameservers =
    `Udp, [ Ipaddr.of_string_exn conf.server_endpoint, conf.server_dns_port ]
  in
  let client = Client.create ~nameservers ~timeout:5_000_000_000L ~sw ~net ~clock () in
  match Client.get_resource_record client Dns.Rr_map.Txt (Utils.name "key.vpn.local") with
  | Ok (_ttl, txt_set) ->
    let record = Dns.Rr_map.Txt_set.elements txt_set |> List.hd in
    record
  | _ -> None
;;

let fetch_peer_endpoint
      ~server_key
      ~hst_pub_key
      ~hst_priv_key
      ~dest_pub_key
      ~sock
      ~clock
      (conf : Config.t)
  : R.t Option.t
  =
  let packet =
    P.create
      ~source:51820
      ~dest_port:conf.server_port
      ~hst_key:hst_pub_key
      ~dest_key:dest_pub_key
      ~priv_key:
        (hst_priv_key
         |> K.to_string
         |> Wg_nat.Crypto.X25519.secret_of_octets ~compress:false
         |> Result.ok
         |> Option.value_exn
         |> fst)
      ~pub_key:server_key
  in
  P.hexdump_t packet;
  let bytes_sent =
    Wg_nat.Request.RawUdpSock.send
      sock
      packet
      ~dest:
        (Core_unix.ADDR_INET
           (Core_unix.Inet_addr.of_string conf.server_endpoint, conf.server_port))
  in
  Printf.printf "Bytes Sent: %d\n" bytes_sent;
  let reply = R.create_buffer ~hdr:true () in
  match
    Eio.Time.with_timeout clock 2.0 (fun () ->
      Ok (Core_unix.recv sock ~buf:reply ~pos:0 ~len:R.sizeof_t ~mode:[]))
  with
  | Error `Timeout -> None
  | Ok recieved ->
    (* let recieved = Core_unix.recv sock ~buf:reply ~pos:0 ~len:R.sizeof_t ~mode:[] in *)
    Printf.printf "Recieved: %d Bytes\n" recieved;
    let reply = R.of_bytes ~hdr:true reply in
    R.hexdump_t reply;
    (match R.get_t_found reply |> R.int_to_found with
     | None ->
       Logs.info (fun m -> m "Invalid Response");
       None
     | Some R.Not_Found -> None
     | Some R.Found -> Some reply)
;;

let main server_key (conf : Config.t) ~clock =
  let wg_intrf = Wgctrl.get_wg_intrf conf in
  let priv_key = wg_intrf.private_key |> Option.value_exn in
  let dest_keys = List.map ~f:(fun p -> p.public_key) wg_intrf.peers |> List.filter_opt in
  List.iter dest_keys ~f:(fun dest_key ->
    Logs.info (fun m -> m "Query Peer:%s\n" (K.to_base64_string dest_key));
    let pub_key = wg_intrf.public_key |> Option.value_exn in
    let sock = Wg_nat.Request.RawUdpSock.init () in
    Bpf_filter.attach_filter
      ~sock
      ~server_ip:(Core_unix.Inet_addr.of_string conf.server_endpoint)
      ~server_port:conf.server_port
      ~wg_port:conf.wg_port;
    let reply =
      fetch_peer_endpoint
        ~server_key
        ~hst_pub_key:pub_key
        ~hst_priv_key:priv_key
        ~dest_pub_key:dest_key
        ~sock
        ~clock
        conf
    in
    match reply with
    | Some reply ->
      Wgctrl.update_peer
        wg_intrf
        dest_key
        (R.get_t_addr reply |> Option.value_exn)
        (R.get_t_port reply)
      |> (function
       | Ok () -> ()
       | Error err ->
         Logs.warn (fun m ->
           m
             "Failed to set wg interface: %s"
             (Wglib.Wgapi.Interface.DeviceError.to_string err)))
    | None -> Logs.info (fun m -> m "Invalid Response"))
;;

let tofu = Tofu.read_known_servers ()

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs.format_reporter ());
  Eio_main.run
  @@ fun env ->
  (* Initialize random number generator *)
  Mirage_crypto_rng_unix.use_default ();
  let conf = get_config () in
  let net : Eio_unix.Net.t = (Eio.Stdenv.net env :> Eio_unix.Net.t) in
  let clock = Eio.Stdenv.clock env in
  let key = get_key ~net ~clock conf |> Option.value_exn ~message:"Dns not reachable" in
  let tofu, authed = Tofu.authenticate tofu Tofu.{ key; endpoint = "127.0.0.1", 5354 } in
  Tofu.write_known_servers tofu;
  match authed with
  | true -> main key conf ~clock
  | false -> Logs.err @@ fun m -> m "Server not authenticated"
;;
