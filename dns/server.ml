(* DNS Server using Eio - multicore ready *)

(* Configuration *)
let listen_port = 5354
let upstream_ip = Eio.Net.Ipaddr.of_raw "\008\008\008\008" (* 8.8.8.8 *)
let upstream_port = 53

(* Helper to create domain names *)
let name s = Domain_name.(host_exn (of_string_exn s))
let raw s = Domain_name.(of_string_exn s)

(* Convert Eio IP address to Ipaddr *)
let eio_to_ipaddr (ip : Eio.Net.Ipaddr.v4v6) : Ipaddr.t =
  let str = Format.asprintf "%a" Eio.Net.Ipaddr.pp ip in
  Ipaddr.of_string_exn str
;;

(* DNS Server state with mutex protection *)
module Server_state = struct
  type t =
    { mutable server : Dns_server.Primary.s
    ; mutex : Eio.Mutex.t
    }

  let create trie =
    let rng = Mirage_crypto_rng.generate ?g:None in
    let server = Dns_server.Primary.create ~rng trie in
    { server; mutex = Eio.Mutex.create () }
  ;;

  let handle_request t ~now ~ts ~proto ~src ~src_port buf =
    Eio.Mutex.use_rw ~protect:true t.mutex
    @@ fun () ->
    let new_server, replies, _notifications, _notify, _key =
      Dns_server.Primary.handle_buf t.server now ts proto src src_port buf
    in
    t.server <- new_server;
    replies
  ;;

  let update t f =
    Eio.Mutex.use_rw ~protect:true t.mutex @@ fun () -> t.server <- f t.server
  ;;
end

(* Build initial local zone *)
let build_initial_trie () =
  let open Dns in
  let zone = name "vpn.local" in
  let soa =
    Soa.
      { nameserver = raw "ns1.vpn.local"
      ; hostmaster = raw "admin.vpn.local"
      ; serial = 2024010101l
      ; refresh = 86400l
      ; retry = 7200l
      ; expiry = 3600000l
      ; minimum = 3600l
      }
  in
  let ns_set = Domain_name.Host_set.(empty |> add (name "ns1.vpn.local")) in
  let ns1_a = 300l, Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn "192.168.1.1") in
  let www_a = 300l, Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn "192.168.1.10") in
  let api_a = 300l, Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn "192.168.1.20") in
  let zone_txt =
    300l, Rr_map.Txt_set.(empty |> add "v=spf1 -all" |> add "This is my local DNS zone")
  in
  let api_txt = 300l, Rr_map.Txt_set.singleton "api-version=v1.2.3" in
  let mx =
    ( 300l
    , Rr_map.Mx_set.singleton
        { Mx.preference = 10; mail_exchange = name "mail.vpn.local" } )
  in
  let mail_a = 300l, Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn "192.168.1.25") in
  Dns_trie.empty
  |> Dns_trie.insert zone Rr_map.Soa soa
  |> Dns_trie.insert zone Rr_map.Ns (300l, ns_set)
  |> Dns_trie.insert zone Rr_map.Txt zone_txt
  |> Dns_trie.insert zone Rr_map.Mx mx
  |> Dns_trie.insert (name "ns1.vpn.local") Rr_map.A ns1_a
  |> Dns_trie.insert (name "www.vpn.local") Rr_map.A www_a
  |> Dns_trie.insert (name "api.vpn.local") Rr_map.A api_a
  |> Dns_trie.insert (name "api.vpn.local") Rr_map.Txt api_txt
  |> Dns_trie.insert (name "mail.vpn.local") Rr_map.A mail_a
;;

(* Forward query to upstream DNS *)
let forward_query ~net ~clock query_buf =
  Eio.Switch.run
  @@ fun sw ->
  let upstream = `Udp (upstream_ip, upstream_port) in
  let sock = Eio.Net.datagram_socket ~sw net `UdpV4 in
  Eio.Net.send sock ~dst:upstream [ query_buf ];
  let resp_buf = Cstruct.create 4096 in
  match Eio.Time.with_timeout clock 2.0 (fun () -> Ok (Eio.Net.recv sock resp_buf)) with
  | Ok (_addr, len) -> Some (Cstruct.sub resp_buf 0 len)
  | Error `Timeout ->
    Logs.warn (fun m -> m "Upstream timeout");
    None
;;

(* Handle a single DNS query *)
let handle_query ~net ~clock ~now server_state src src_port query_buf =
  let open Dns in
  let query_str = Cstruct.to_string query_buf in
  (* Check if query is for our local zone *)
  match Packet.decode query_str with
  | Error _ -> None
  | Ok query ->
    (match query.Packet.data with
     | `Query ->
       let name, _q_type = query.Packet.question in
       let domain_str = Domain_name.to_string name in
       (* Check if this is for our local zone *)
       if String.ends_with ~suffix:".vpn.local" domain_str
          || domain_str = "vpn.local"
       then (
         (* Query is for our zone, use local DNS server *)
         let ts = Int64.of_float (Ptime.Span.to_float_s (Ptime.to_span now)) in
         let replies =
           Server_state.handle_request server_state ~now ~ts ~proto:`Udp ~src ~src_port
             query_str
         in
         match replies with
         | reply :: _ ->
           Logs.info (fun m -> m "-> Local: %s" domain_str);
           Some (Cstruct.of_string reply)
         | [] -> None)
       else (
         (* Not our zone, forward to upstream *)
         Logs.info (fun m -> m "-> Forward: %s" domain_str);
         forward_query ~net ~clock query_buf)
     | _ -> None)
;;

(* DNS server - listens for queries and spawns fibers to handle them *)
let dns_server ~net ~clock server_state =
  Eio.Switch.run
  @@ fun sw ->
  let listening_addr = `Udp (Eio.Net.Ipaddr.V4.any, listen_port) in
  let sock = Eio.Net.datagram_socket ~sw net listening_addr in
  Logs.info (fun m -> m "DNS server listening on port %d" listen_port);
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
    let src = eio_to_ipaddr eio_ip in
    (* Spawn a fiber to handle this query concurrently *)
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
    Server_state.update server_state (fun server ->
      let trie = Dns_server.Primary.data server in
      let new_trie = Dns_trie.insert dynamic_name Dns.Rr_map.A a_record trie in
      let rng = Mirage_crypto_rng.generate ?g:None in
      Dns_server.Primary.create ~rng new_trie);
    Logs.info (fun m ->
      m "Added record: %a -> %a" Domain_name.pp dynamic_name Ipaddr.V4.pp ip)
  done
;;

(* Example: CPU-bound work on a separate domain *)
let _run_on_domain ~domain_mgr f = Eio.Domain_manager.run domain_mgr f

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs.format_reporter ());
  Eio_main.run
  @@ fun env ->
  (* Initialize random number generator *)
  Mirage_crypto_rng_unix.use_default ();
  let net = Eio.Stdenv.net env in
  let clock = Eio.Stdenv.clock env in
  let _domain_mgr = Eio.Stdenv.domain_mgr env in
  (* Create DNS server state *)
  let server_state = Server_state.create (build_initial_trie ()) in
  Logs.info (fun m -> m "Loaded initial DNS records");
  (* Run DNS server and background populator concurrently *)
  Eio.Fiber.both
    (fun () -> dns_server ~net ~clock server_state)
    (fun () -> record_populator ~clock server_state)
;;
