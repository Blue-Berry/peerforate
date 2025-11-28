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

let int_to_hex i = Printf.sprintf "%02x" i

let string_to_hex s =
  String.to_sequence s
  |> Sequence.map ~f:(fun c -> Char.to_int c |> int_to_hex)
  |> Sequence.to_list
  |> String.concat
;;

module Config = struct
  let listen_port = 49918
  let max_message_age_s = 2.0
end

let main ~net =
  Eio.Switch.run
  @@ fun sw ->
  let listening_addr = `Udp (Eio.Net.Ipaddr.V4.any, Config.listen_port) in
  let sock = Eio.Net.datagram_socket ~sw net listening_addr in
  let buf = Cstruct.create 4096 in
  while true do
    let client_addr, len = Eio.Net.recv sock buf in
    Logs.info (fun m ->
      m
        "Received %d bytes from %a; Expected: %d\n"
        len
        Eio.Net.Sockaddr.pp
        client_addr
        P.payload_size);
    if len < P.payload_size
    then Logs.info (fun m -> m "Invalid packetsize %d" len)
    else (
      let packet = P.of_cstruct ~hdr:false buf in
      let hst_key = P.copy_t_hst_key packet |> K.of_string in
      let dest_key = P.copy_t_dest_key packet |> K.of_string in
      let timestamp = P.get_t_timestamp packet in
      let mac = P.copy_t_mac packet |> string_to_hex in
      Logs.info (fun m ->
        m
          "Version: %d\nHost key: %s\nDest key %s\nTimestamp: %s\nMAC: %s"
          (P.get_t_version packet)
          (hst_key |> K.to_base64_string)
          (dest_key |> K.to_base64_string)
          (Int64.to_string_hum timestamp)
          mac);
      let mac =
        P.gen_mac
          ~pub_key:(hst_key |> K.to_string)
          ~priv_key:Wg_nat.Crypto.rng_priv_key
          ~hst_key:(K.to_string hst_key)
          ~dest_key:(K.to_string dest_key)
          timestamp
        |> string_to_hex
      in
      let now =
        Ptime.v (Ptime_clock.now_d_ps ()) |> Ptime.to_span |> Ptime.Span.to_float_s
      in
      let timestamp = Int64.to_float timestamp in
      let age = now -. timestamp in
      if Float.(age < Config.max_message_age_s) && Float.(age >= 0.)
      then (
        Logs.info (fun m -> m "Generated MAC %s" mac);
        let reply = R.create ~hst_key ~dest_key () |> R.to_cstruct ~hdr:false in
        Eio.Net.send sock [ reply ] ~dst:client_addr;
        Logs.info (fun m -> m "Sent reply to %a\n" Eio.Net.Sockaddr.pp client_addr))
      else Logs.info (fun m -> m "Message too old"))
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
