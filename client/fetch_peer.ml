open! Core
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

let fetch_peer_endpoint
      ~source_port
      ~server_key
      ~hst_pub_key
      ~hst_priv_key
      ~dest_pub_key
      ~sock
      ~clock
      (conf : Config.t)
  : R.t Option.t
  =
  let packet =
    P.create
      ~source_port
      ~dest_port:conf.server_port
      ~hst_key:hst_pub_key
      ~dest_key:dest_pub_key
      ~priv_key:
        (hst_priv_key
         |> K.to_string
         |> Wg_nat.Crypto.X25519.secret_of_octets ~compress:false
         |> Result.ok
         |> Option.value_exn
         |> fst)
      ~pub_key:server_key
  in
  P.hexdump_t packet;
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
  match
    Eio.Time.with_timeout clock 2.0 (fun () ->
      Ok (Core_unix.recv sock ~buf:reply ~pos:0 ~len:R.sizeof_t ~mode:[]))
  with
  | Error `Timeout -> None
  | Ok recieved ->
    (* let recieved = Core_unix.recv sock ~buf:reply ~pos:0 ~len:R.sizeof_t ~mode:[] in *)
    Printf.printf "Recieved: %d Bytes\n" recieved;
    let reply = R.of_bytes ~hdr:true reply in
    R.hexdump_t reply;
    (match R.get_t_found reply |> R.int_to_found with
     | None ->
       Logs.info (fun m -> m "Invalid Response");
       None
     | Some R.Not_Found -> None
     | Some R.Found -> Some reply)
;;
