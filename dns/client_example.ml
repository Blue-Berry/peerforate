open Dnslib.Client

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs.format_reporter ());
  Eio_main.run
  @@ fun env ->
  (* Initialize random number generator *)
  Mirage_crypto_rng_unix.use_default ();
  let net = Eio.Stdenv.net env in
  let clock = Eio.Stdenv.clock env in
  (* DNS server to query (localhost:5354 - our local DNS server) *)
  let dns_server = `Udp (Eio.Net.Ipaddr.V4.loopback, 5354) in
  Eio.Switch.run
  @@ fun sw ->
  (* Query for the encryption key from key.vpn.local *)
  Logs.info (fun m -> m "Querying TXT record for key.vpn.local...");
  (match get_key ~sw ~net ~dst:dns_server ~clock with
   | Some key ->
     Logs.info (fun m -> m "Retrieved key: %s" key);
     print_endline ("Key: " ^ key)
   | None ->
     Logs.warn (fun m -> m "Failed to retrieve key");
     print_endline "Failed to retrieve key");
  (* Query for any domain's TXT records *)
  Logs.info (fun m -> m "Querying TXT records for google.com...");
  match get_txt_records ~sw ~net ~dst:dns_server ~clock "google.com" with
  | Ok records ->
    Logs.info (fun m -> m "Found %d TXT records" (List.length records));
    List.iter (fun txt -> print_endline ("TXT: " ^ txt)) records
  | Error _ ->
    Logs.warn (fun m -> m "Failed to query google.com");
    print_endline "Failed to query google.com"
;;
