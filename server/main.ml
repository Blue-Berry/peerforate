open! Core
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

(* TODO: *)
(*   - Track Clients: public key, timestamp, address *)
(*   - timeout for clients, lazy cleanup + periodic cleanup *)
(*   - Authenticate client before tracking *)
(*   - Prevent DoS *)
(*   - Refactor *)
(*   - Add tests *)
(*   - Switch to ipv6 *)
(* add timeouit for client recv  *)

(* let int_to_hex i = Printf.sprintf "%02x" i *)

(* let string_to_hex s = *)
(*   String.to_sequence s *)
(*   |> Sequence.map ~f:(fun c -> Char.to_int c |> int_to_hex) *)
(*   |> Sequence.to_list *)
(*   |> String.concat *)
(* ;; *)

let main ~net =
  Eio.Switch.run
  @@ fun sw ->
  let listening_addr = `Udp (Eio.Net.Ipaddr.V4.any, Config.listen_port) in
  let sock = Eio.Net.datagram_socket ~sw net listening_addr in
  let buf = Cstruct.create 4096 in
  let client_map = Client_map.create () in
  while true do
    let client_addr, len = Eio.Net.recv sock buf in
    if len < P.payload_size
    then Logs.info (fun m -> m "Invalid packetsize %d" len)
    else (
      match client_addr with
      | `Udp (ip, port) ->
        let packet = P.of_cstruct ~hdr:false (Cstruct.sub buf 0 len) in
        Eio.Net.Ipaddr.fold
          ~v4:(fun ip ->
            let ip = Dnslib.Utils.eio_to_ipaddr ip in
            match Auth.is_valid_timestamp packet, Auth.is_valid_mac packet with
            | true, true ->
              (match
                 Client_map.handle_packet
                   client_map
                   packet
                   ~client_addr:ip
                   ~client_port:port
               with
               | None -> ()
               | Some (addr, port) ->
                 let reply =
                   R.create ~found:R.Found ~endpoint:addr ~port ()
                   |> R.to_cstruct ~hdr:false
                 in
                 Eio.Net.send sock [ reply ] ~dst:client_addr;
                 Logs.info (fun m ->
                   m "Sent reply to %a\n" Eio.Net.Sockaddr.pp client_addr))
            | false, _ -> Logs.info (fun m -> m "Message too old")
            | _, false -> Logs.info (fun m -> m "Message Invalid MAC"))
          ~v6:(fun _ -> Logs.info (fun m -> m "Can't handle ipv6"))
          ip
      | _ -> Logs.info (fun m -> m "Invalid client socket address"))
  done
;;

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
  Eio.Fiber.both
    (fun () ->
       let open Dnslib.Server in
       let open Dnslib in
       let server_state = State.create (build_trie ()) in
       let key_txt = 300l, Dns.Rr_map.Txt_set.singleton Wg_nat.Crypto.rng_pub_key in
       add_record
         server_state
         ~name:(Config.with_zone "key" |> Utils.name)
         ~key:Dns.Rr_map.Txt
         ~value:key_txt;
       Eio.Domain_manager.run domain_mgr (fun () -> dns_serve ~net ~clock server_state))
    (fun () -> main ~net)
;;
