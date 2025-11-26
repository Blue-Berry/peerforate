open Dnslib.Server

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs.format_reporter ());
  Eio_main.run
  @@ fun env ->
  (* Initialize random number generator *)
  Mirage_crypto_rng_unix.use_default ();
  let net = Eio.Stdenv.net env in
  let clock = Eio.Stdenv.clock env in
  let domain_mgr = Eio.Stdenv.domain_mgr env in
  (* Create DNS server state *)
  let server_state = State.create (build_trie ()) in
  Logs.info (fun m -> m "Loaded initial DNS records");
  (* Run DNS server on main domain, background populator on separate domain *)
  Eio.Fiber.both
    (fun () ->
       Logs.info (fun m -> m "DNS server running on main domain");
       dns_serve ~net ~clock server_state)
    (fun () ->
       Logs.info (fun m -> m "Record populator running on separate domain");
       Eio.Domain_manager.run domain_mgr (fun () -> record_populator ~clock server_state))
;;
