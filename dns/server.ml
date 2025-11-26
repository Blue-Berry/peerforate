(* DNS Server using Eio - multicore ready *)

(* Configuration *)
let listen_port = 5353
let upstream_ip = Eio.Net.Ipaddr.of_raw "\008\008\008\008" (* 8.8.8.8 *)
let upstream_port = 53

(* Helper to create domain names *)
let name s = Domain_name.(host_exn (of_string_exn s))
let raw s = Domain_name.(of_string_exn s)

(* Shared DNS records with mutex protection *)
module Records = struct
  type t =
    { mutable trie : Dns_trie.t
    ; mutex : Eio.Mutex.t
    }

  let create trie = { trie; mutex = Eio.Mutex.create () }

  let lookup t name qtype =
    Eio.Mutex.use_ro t.mutex
    @@ fun () ->
    match Dns_trie.lookup name qtype t.trie with
    | Ok rr -> Some rr
    | Error _ -> None
  ;;

  let update t f = Eio.Mutex.use_rw ~protect:true t.mutex @@ fun () -> t.trie <- f t.trie
end

(* Build initial local zone *)
let build_initial_trie () =
  let open Dns in
  let zone = name "example.local" in
  let soa =
    Soa.
      { nameserver = raw "ns1.example.local"
      ; hostmaster = raw "admin.example.local"
      ; serial = 2024010101l
      ; refresh = 86400l
      ; retry = 7200l
      ; expiry = 3600000l
      ; minimum = 3600l
      }
  in
  let ns_set = Domain_name.Host_set.(empty |> add (name "ns1.example.local")) in
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
        { Mx.preference = 10; mail_exchange = name "mail.example.local" } )
  in
  let mail_a = 300l, Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn "192.168.1.25") in
  Dns_trie.empty
  |> Dns_trie.insert zone Rr_map.Soa soa
  |> Dns_trie.insert zone Rr_map.Ns (300l, ns_set)
  |> Dns_trie.insert zone Rr_map.Txt zone_txt
  |> Dns_trie.insert zone Rr_map.Mx mx
  |> Dns_trie.insert (name "ns1.example.local") Rr_map.A ns1_a
  |> Dns_trie.insert (name "www.example.local") Rr_map.A www_a
  |> Dns_trie.insert (name "api.example.local") Rr_map.A api_a
  |> Dns_trie.insert (name "api.example.local") Rr_map.Txt api_txt
  |> Dns_trie.insert (name "mail.example.local") Rr_map.A mail_a
;;

(* Forward query to upstream DNS *)
let forward_query ~net ~clock query_buf =
  Eio.Switch.run
  @@ fun sw ->
  let upstream = `Udp (upstream_ip, upstream_port) in
  let sock = Eio.Net.datagram_socket ~sw net `UdpV4 in
  Eio.Net.send sock upstream [ query_buf ];
  let resp_buf = Cstruct.create 4096 in
  match Eio.Time.with_timeout clock 2.0 (fun () -> Eio.Net.recv sock resp_buf) with
  | Ok (_addr, len) -> Some (Cstruct.sub resp_buf 0 len)
  | Error `Timeout ->
    Logs.warn (fun m -> m "Upstream timeout");
    None
;;

(* Build a DNS response packet *)
let make_response (query : Dns.Packet.t) answer =
  let open Dns.Packet in
  let header = { query.header with Dns.Packet.Header.query = false } in
  create header (`Answer (answer, Dns.Name_rr_map.empty))
;;

(* Handle a single DNS query *)
let handle_query ~net ~clock records query_buf =
  let open Dns in
  match Packet.decode query_buf with
  | Error e ->
    Logs.warn (fun m -> m "Decode error: %a" Packet.pp_err e);
    None
  | Ok query ->
    (match query.Packet.data with
     | `Query ->
       (match query.Packet.questions with
        | [ { Question.name; q_type } ] ->
          Logs.info (fun m ->
            m "Query: %a %a" Domain_name.pp name Packet.Question.pp_qtype q_type);
          (* Try local first *)
          let local_answer =
            match q_type with
            | `K (Rr_map.K k) -> Records.lookup records (Domain_name.raw name) k
            | `Any | `Axfr _ | `Ixfr -> None
          in
          (match local_answer with
           | Some rr ->
             Logs.info (fun m -> m "-> Local");
             let answer = Domain_name.Map.singleton (Domain_name.raw name) rr in
             let pkt = make_response query answer in
             (match Packet.encode `Udp pkt with
              | Ok (cs, _) -> Some cs
              | Error _ -> None)
           | None ->
             Logs.info (fun m -> m "-> Forward");
             forward_query ~net ~clock query_buf)
        | _ -> None)
     | _ -> None)
;;

(* DNS server - listens for queries and spawns fibers to handle them *)
let dns_server ~net ~clock records =
  Eio.Switch.run
  @@ fun sw ->
  let listening_addr = `Udp (Eio.Net.Ipaddr.V4.any, listen_port) in
  let sock = Eio.Net.datagram_socket ~sw net listening_addr in
  Logs.info (fun m -> m "DNS server listening on port %d" listen_port);
  let buf = Cstruct.create 4096 in
  while true do
    let client_addr, len = Eio.Net.recv sock buf in
    let query_buf = Cstruct.sub buf 0 len in
    (* Spawn a fiber to handle this query concurrently *)
    Eio.Fiber.fork ~sw (fun () ->
      match handle_query ~net ~clock records query_buf with
      | Some resp -> Eio.Net.send sock client_addr [ resp ]
      | None -> ())
  done
;;

(* Example background task: periodically update records *)
let record_populator ~clock records =
  let counter = ref 0 in
  while true do
    Eio.Time.sleep clock 10.0;
    incr counter;
    (* Example: add a dynamic record *)
    let dynamic_name = name (Printf.sprintf "dynamic%d.example.local" !counter) in
    let ip =
      Ipaddr.V4.of_string_exn (Printf.sprintf "10.0.0.%d" (1 + (!counter mod 254)))
    in
    let a_record = 60l, Ipaddr.V4.Set.singleton ip in
    Records.update records (fun trie ->
      Dns_trie.insert dynamic_name Dns.Rr_map.A a_record trie);
    Logs.info (fun m ->
      m "Added record: %a -> %a" Domain_name.pp dynamic_name Ipaddr.V4.pp ip)
  done
;;

(* Example: CPU-bound work on a separate domain *)
let run_on_domain ~domain_mgr f = Eio.Domain_manager.run domain_mgr f

let () =
  Fmt_tty.setup_std_outputs ();
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs_fmt.reporter ());
  Eio_main.run
  @@ fun env ->
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env
  @@ fun () ->
  let net = Eio.Stdenv.net env in
  let clock = Eio.Stdenv.clock env in
  let _domain_mgr = Eio.Stdenv.domain_mgr env in
  (* Create shared records *)
  let records = Records.create (build_initial_trie ()) in
  Logs.info (fun m -> m "Loaded initial DNS records");
  (* Run DNS server and background populator concurrently *)
  Eio.Fiber.both
    (fun () -> dns_server ~net ~clock records)
    (fun () -> record_populator ~clock records)
;;
