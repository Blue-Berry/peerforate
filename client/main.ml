open! Core
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

(* TODO: *)
(* - eBPF nat check when packet is being sent *)

let get_config () =
  Config.read_config ()
  |> function
  | Some c -> c
  | None ->
    Config.init_config ~server_endpoint:"127.0.0.1" ~server_port:49918 ~wg_interface:"wg8"
;;

let get_key ~net ~clock (conf : Config.t) =
  let open Dnslib in
  Eio.Switch.run
  @@ fun sw ->
  let nameservers =
    `Udp, [ Ipaddr.of_string_exn conf.server_endpoint, conf.server_dns_port ]
  in
  let client = Client.create ~nameservers ~timeout:5_000_000_000L ~sw ~net ~clock () in
  match Client.get_resource_record client Dns.Rr_map.Txt (Utils.name "key.vpn.local") with
  | Ok (_ttl, txt_set) ->
    let record = Dns.Rr_map.Txt_set.elements txt_set |> List.hd in
    record
  | _ -> None
;;

let main server_key (conf : Config.t) =
  let wg_intrf = Wgctrl.get_wg_intrf conf in
  let sock = Wg_nat.Request.RawUdpSock.init () in
  let key = Wglib.Wgapi.Key.generate_private_key () in
  Printf.printf "key: %s\n" (Wglib.Wgapi.Key.to_base64_string (K.generate_public_key key));
  Bpf_filter.attach_filter
    ~sock
    ~server_ip:(Core_unix.Inet_addr.of_string conf.server_endpoint)
    ~server_port:conf.server_port
    ~wg_port:51820;
  let packet =
    P.create
      ~source:51820
      ~dest_port:conf.server_port
      ~hst_key:(K.generate_public_key key)
      ~dest_key:(K.generate_public_key key)
      ~priv_key:
        (key
         |> K.to_string
         |> Wg_nat.Crypto.X25519.secret_of_octets ~compress:false
         |> Result.ok
         |> Option.value_exn
         |> fst)
      ~pub_key:server_key
  in
  Printf.sprintf "MAC: %s\n" (P.copy_t_mac packet |> Base64.encode_string)
  |> print_endline;
  let bytes_sent =
    Wg_nat.Request.RawUdpSock.send
      sock
      packet
      ~dest:
        (Core_unix.ADDR_INET
           (Core_unix.Inet_addr.of_string conf.server_endpoint, conf.server_port))
  in
  Printf.printf "Bytes Sent: %d\n" bytes_sent;
  let reply = R.create_buffer ~hdr:true () in
  let recieved = Core_unix.recv sock ~buf:reply ~pos:0 ~len:R.sizeof_t ~mode:[] in
  Printf.printf "Recieved: %d Bytes\n" recieved;
  let reply = R.of_bytes ~hdr:true reply in
  R.hexdump_t reply;
  Wgctrl.update_peer
    wg_intrf
    key
    (R.get_t_addr reply |> Option.value_exn)
    (R.get_t_port reply)
  |> ignore
;;

(* Wgctrl.update_peer wg_intrf key () *)

let tofu = Tofu.read_known_servers ()

let () =
  Eio_main.run
  @@ fun env ->
  (* Initialize random number generator *)
  Mirage_crypto_rng_unix.use_default ();
  let conf = get_config () in
  let net : Eio_unix.Net.t = (Eio.Stdenv.net env :> Eio_unix.Net.t) in
  let clock = Eio.Stdenv.clock env in
  let key = get_key ~net ~clock conf |> Option.value_exn in
  let tofu, authed = Tofu.authenticate tofu Tofu.{ key; endpoint = "127.0.0.1", 5354 } in
  Tofu.write_known_servers tofu;
  match authed with
  | true -> main key conf
  | false -> print_endline "Server not authenticated"
;;
