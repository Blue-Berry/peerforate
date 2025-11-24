open! Core
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

(* TODO: *)
(*   - Periodic update of address (set dest_key to null) *)
(* - eBPF nat check when packet is being sent *)

let int_to_hex i = Printf.sprintf "%02x" i

let string_to_hex s =
  String.to_sequence s
  |> Sequence.map ~f:(fun c -> Char.to_int c |> int_to_hex)
  |> Sequence.to_list
  |> String.concat
;;

let () =
  let sock = Wg_nat.Request.RawUdpSock.init () in
  let key = Wglib.Wgapi.Key.generate_private_key () in
  Printf.printf "key: %s\n" (Wglib.Wgapi.Key.to_base64_string (K.generate_public_key key));
  Bpf_filter.attach_filter
    ~sock
    ~server_ip:(Core_unix.Inet_addr.of_string "127.0.0.1")
    ~server_port:49918
    ~wg_port:51820;
  let packet =
    P.create
      ~source:51820
      ~dest_port:49918
      ~hst_key:(K.generate_public_key key)
      ~dest_key:(K.generate_public_key key)
      ~priv_key:
        (key
         |> K.to_string
         |> Wg_nat.Crypto.X25519.secret_of_octets ~compress:false
         |> Result.ok
         |> Option.value_exn
         |> fst)
      ~pub_key:Wg_nat.Crypto.rng_pub_key
  in
  Printf.sprintf "MAC: %s\n" (P.copy_t_mac packet |> string_to_hex) |> print_endline;
  let bytes_sent =
    Wg_nat.Request.RawUdpSock.send
      sock
      packet
      ~dest:(Core_unix.ADDR_INET (Core_unix.Inet_addr.of_string "127.0.0.1", 49918))
  in
  Printf.printf "Bytes Sent: %d\n" bytes_sent;
  let reply = R.create_buffer ~hdr:true () in
  let recieved = Core_unix.recv sock ~buf:reply ~pos:0 ~len:R.sizeof_t ~mode:[] in
  Printf.printf "Recieved: %d Bytes\n" recieved;
  let reply = R.of_bytes ~hdr:true reply in
  Printf.sprintf
    "Reply: \n\tVersion: %d\n\thost key: %s\n\tdest key %s\n"
    (R.get_t_version reply)
    (R.copy_t_hst_key reply |> K.of_string |> K.to_base64_string)
    (R.copy_t_dest_key reply |> K.of_string |> K.to_base64_string)
  |> print_endline
;;
