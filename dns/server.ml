open Core

let name s = Domain_name.(host_exn (of_string_exn s))

module Config = struct
  let listen_port = 5354
  let upstream_ip = Eio.Net.Ipaddr.of_raw "\008\008\008\008" (* 8.8.8.8 *)
  let upstream_port = 53
  let zone_str = "vpn.local"

  let zone =
    let open Domain_name in
    let host_str = of_string zone_str in
    let host = Result.bind host_str ~f:(fun s -> host s) in
    Result.map_error host ~f:(function `Msg m ->
        String.append "Failed to create zone: " m)
    |> Result.ok_or_failwith
  ;;

  let serial = 2024010101l
  let refresh = 86400l
  let retry = 7200l
  let expiry = 3600000l
  let minimum = 3600l
end

module State = struct
  type t =
    { mutable server : Dns_server.Primary.s
    ; mutex : Eio.Mutex.t
    }

  let create trie =
    let rng = Mirage_crypto_rng.generate in
    let server = Dns_server.Primary.create ~rng trie in
    { server; mutex = Eio.Mutex.create () }
  ;;

  let update ~f t =
    Eio.Mutex.use_rw ~protect:true t.mutex (fun () -> t.server <- f t.server)
  ;;

  let handle_request t ~now ~ts ~proto ~src ~src_port ~buf =
    Eio.Mutex.use_rw ~protect:true t.mutex (fun () ->
      let server, replies, _, _, _ =
        Dns_server.Primary.handle_buf t.server now ts proto src src_port buf
      in
      t.server <- server;
      replies)
  ;;
end

let build_trie () =
  let raw s =
    Domain_name.(of_string s)
    |> Result.map_error ~f:(function `Msg m ->
        String.append "Failed to create domain: " m)
    |> Result.ok_or_failwith
  in
  let open Dns in
  let soa =
    Config.(
      Soa.
        { nameserver = raw (String.append "ns1" Config.zone_str)
        ; hostmaster = raw (String.append "admin" Config.zone_str)
        ; serial
        ; refresh
        ; retry
        ; expiry
        ; minimum
        })
  in
  let key_txt = 300l, Rr_map.Txt_set.singleton Wg_nat.Crypto.rng_pub_key in
  Dns_trie.empty
  |> Dns_trie.insert Config.zone Rr_map.Soa soa
  |> Dns_trie.insert (name "key.vpn.local") Rr_map.Txt key_txt
;;

let forward_query ~net ~clock query_buf =
  Eio.Switch.run
  @@ fun sw ->
  let upstream = `Udp Config.(upstream_ip, upstream_port) in
  let sock = Eio.Net.datagram_socket ~sw net `UdpV4 in
  Eio.Net.send sock ~dst:upstream [ query_buf ];
  let resp_buf = Cstruct.create 4096 in
  match Eio.Time.with_timeout clock 2.0 (fun () -> Ok (Eio.Net.recv sock resp_buf)) with
  | Ok (_addr, len) -> Some (Cstruct.sub resp_buf 0 len)
  | Error `Timeout ->
    Logs.warn (fun m -> m "Upstream timeout");
    None
;;

let is_local_zone name =
  let domain_str = Domain_name.to_string name in
  String.is_suffix ~suffix:Config.zone_str domain_str
  || String.equal domain_str Config.zone_str
;;

let handle_query ~net ~clock ~now server_state src src_port query_buf =
  let open Dns in
  let query_str = Cstruct.to_string query_buf in
  match Packet.decode query_str with
  | Error _ -> None
  | Ok query ->
    (match query.Packet.data with
     | `Query ->
       let name, _q_type = query.Packet.question in
       if is_local_zone name
       then (
         let ts = Int64.of_float (Ptime.Span.to_float_s (Ptime.to_span now)) in
         let replies =
           State.handle_request
             server_state
             ~now
             ~ts
             ~proto:`Udp
             ~src
             ~src_port
             ~buf:query_str
         in
         (* NOTE: Only handle single replies *)
         match replies with
         | reply :: _ ->
           Logs.info (fun m -> m "-> Local: %s" (Domain_name.to_string name));
           Some (Cstruct.of_string reply)
         | [] -> None)
       else (
         (* Not our zone, forward to upstream *)
         Logs.info (fun m -> m "-> Forward: %s" (Domain_name.to_string name));
         forward_query ~net ~clock query_buf)
     | _ -> None)
;;

let dns_serve ~net ~clock server_state =
  Eio.Switch.run
  @@ fun sw ->
  let listening_addr = `Udp (Eio.Net.Ipaddr.V4.any, Config.listen_port) in
  let sock = Eio.Net.datagram_socket ~sw net listening_addr in
  Logs.info (fun m -> m "DNS server listening on port %d" Config.listen_port);
  let buf = Cstruct.create 4096 in
  while true do
    let client_addr, len = Eio.Net.recv sock buf in
    let query_buf = Cstruct.sub buf 0 len in
    let now = Ptime.v (Ptime_clock.now_d_ps ()) in
    let eio_ip, src_port =
      match client_addr with
      | `Udp (ip, port) -> ip, port
      | _ -> Eio.Net.Ipaddr.V4.any, 0
    in
    let src = Utils.eio_to_ipaddr eio_ip in
    Eio.Fiber.fork ~sw (fun () ->
      match handle_query ~net ~clock ~now server_state src src_port query_buf with
      | Some resp -> Eio.Net.send sock ~dst:client_addr [ resp ]
      | None -> ())
  done
;;

(* Example background task: periodically update records *)
let record_populator ~clock server_state =
  let counter = ref 0 in
  while true do
    Eio.Time.sleep clock 10.0;
    incr counter;
    (* Example: add a dynamic record *)
    let dynamic_name = name (Printf.sprintf "dynamic%d.vpn.local" !counter) in
    let ip =
      Ipaddr.V4.of_string_exn (Printf.sprintf "10.0.0.%d" (1 + (!counter mod 254)))
    in
    let a_record = 60l, Ipaddr.V4.Set.singleton ip in
    State.update server_state ~f:(fun server ->
      let trie = Dns_server.Primary.data server in
      let new_trie = Dns_trie.insert dynamic_name Dns.Rr_map.A a_record trie in
      let rng = Mirage_crypto_rng.generate ?g:None in
      Dns_server.Primary.create ~rng new_trie);
    Logs.info (fun m ->
      m "Added record: %a -> %a" Domain_name.pp dynamic_name Ipaddr.V4.pp ip)
  done
;;
