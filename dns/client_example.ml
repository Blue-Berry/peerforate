(* Example using Dns_client.Make functor *)
open Dnslib.Client

let name = Dnslib.Utils.name

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs.format_reporter ());
  Eio_main.run
  @@ fun env ->
  (* Initialize random number generator *)
  Mirage_crypto_rng_unix.use_default ();
  let net : Eio_unix.Net.t = (Eio.Stdenv.net env :> Eio_unix.Net.t) in
  let clock = Eio.Stdenv.clock env in
  Eio.Switch.run
  @@ fun sw ->
  (* Create DNS client using the helper function *)
  let nameservers = `Udp, [ Ipaddr.of_string_exn "127.0.0.1", 5354 ] in
  let client = create ~nameservers ~timeout:5_000_000_000L ~sw ~net ~clock () in
  Logs.info (fun m -> m "DNS client created with nameservers: localhost:5354");
  (* Example 1: Query TXT records for key.vpn.local *)
  Logs.info (fun m -> m "Querying TXT records for key.vpn.local...");
  (match get_resource_record client Dns.Rr_map.Txt (name "key.vpn.local") with
   | Ok (_ttl, txt_set) ->
     let records = Dns.Rr_map.Txt_set.elements txt_set in
     Logs.info (fun m -> m "Found %d TXT record(s)" (List.length records));
     List.iter (fun txt -> print_endline ("TXT: " ^ txt)) records
   | Error (`Msg msg) -> Logs.warn (fun m -> m "Query failed: %s" msg)
   | Error (`No_data (domain, _soa)) ->
     Logs.warn (fun m -> m "No TXT data for %s" (Domain_name.to_string domain))
   | Error (`No_domain (domain, _soa)) ->
     Logs.warn (fun m -> m "Domain not found: %s" (Domain_name.to_string domain)));
  (* Example 2: Query A record (IPv4) for a domain *)
  Logs.info (fun m -> m "Querying A record for google.com...");
  (match gethostbyname client (name "google.com") with
   | Ok ipv4 ->
     Logs.info (fun m -> m "Resolved to IPv4: %s" (Ipaddr.V4.to_string ipv4));
     print_endline ("IPv4: " ^ Ipaddr.V4.to_string ipv4)
   | Error (`Msg msg) ->
     Logs.warn (fun m -> m "Failed to resolve google.com: %s" msg);
     print_endline "Failed to resolve google.com");
  (* Example 3: Generic query for TXT records using getaddrinfo *)
  Logs.info (fun m -> m "Querying TXT records for test.vpn.local using getaddrinfo...");
  match getaddrinfo client Dns.Rr_map.Txt (name "test.vpn.local") with
  | Ok (_ttl, txt_set) ->
    let records = Dns.Rr_map.Txt_set.elements txt_set in
    Logs.info (fun m -> m "Found %d TXT record(s)" (List.length records));
    List.iter (fun txt -> print_endline ("TXT: " ^ txt)) records
  | Error (`Msg msg) ->
    Logs.warn (fun m -> m "Query failed: %s" msg);
    print_endline ("Failed: " ^ msg)
;;
