open! Core
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

(* TODO: *)
(*   - Refactor *)
(*   - Add tests *)
(*   - Create DNS server *)
(*   - DNS server forwarding? *)
(*   - Create DNS client *)
(*   - Publish public key to DNS TXT record *)
(*   - Track Clients: public key, timestamp, address *)
(*   - timeout for clients, lazy cleanup + periodic cleanup *)
(*   - Prevent replay attacks *)
(*   - Prevent DoS *)
(*   - Authenticate client before tracking *)

let int_to_hex i = Printf.sprintf "%02x" i

let string_to_hex s =
  String.to_sequence s
  |> Sequence.map ~f:(fun c -> Char.to_int c |> int_to_hex)
  |> Sequence.to_list
  |> String.concat
;;

let () =
  let sock = Core_unix.socket ~domain:PF_INET ~kind:SOCK_DGRAM ~protocol:0 () in
  Core_unix.bind
    sock
    ~addr:(Core_unix.ADDR_INET (Core_unix.Inet_addr.of_string "127.0.0.1", 49918));
  let buf = P.create_buffer () in
  while true do
    let res, addr = Core_unix.recvfrom sock ~buf ~pos:0 ~len:P.payload_size ~mode:[] in
    Printf.printf
      "Received %d bytes from %s\n%!"
      res
      (Core_unix.sexp_of_sockaddr addr |> Sexp.to_string_hum);
    let packet = P.of_bytes buf in
    let hst_key = P.copy_t_hst_key packet |> K.of_string in
    let dest_key = P.copy_t_dest_key packet |> K.of_string in
    let timestamp = P.get_t_timestamp packet in
    let mac = P.copy_t_mac packet |> string_to_hex in
    Printf.sprintf
      "Version: %d\nhost key: %s\ndest key %s\ntimestamp: %d\nMAC: %s\n"
      (P.get_t_version packet)
      (hst_key |> K.to_base64_string)
      (dest_key |> K.to_base64_string)
      (Int64.to_int_exn timestamp)
      mac
    |> print_endline;
    let mac =
      P.gen_mac
        ~pub_key:(hst_key |> K.to_string)
        ~priv_key:Wg_nat.Crypto.rng_priv_key
        ~hst_key:(K.to_string hst_key)
        ~dest_key:(K.to_string dest_key)
        timestamp
      |> string_to_hex
    in
    Printf.sprintf "Generated MAC%s" mac |> print_endline;
    let reply = R.create ~hst_key ~dest_key () |> R.to_bytes ~hdr:false in
    let sent =
      Core_unix.sendto sock ~buf:reply ~pos:0 ~len:R.payload_size ~mode:[] ~addr
    in
    Printf.sprintf
      "Sent %d bytes to %s\n%!"
      sent
      (Core_unix.sexp_of_sockaddr addr |> Sexp.to_string_hum)
    |> print_endline
  done
;;
