let eio_to_ipaddr (ip : Eio.Net.Ipaddr.v4v6) : Ipaddr.t =
  let str = Format.asprintf "%a" Eio.Net.Ipaddr.pp ip in
  Ipaddr.of_string_exn str
;;

let ipaddr_to_eio (ip : Ipaddr.t) : Eio.Net.Ipaddr.v4v6 =
  Eio.Net.Ipaddr.of_raw (Ipaddr.to_octets ip)
;;

(* TODO: move back *)
let query ~sw ~net ~dst ~query_buf ~clock =
  let sock = Eio.Net.datagram_socket ~sw net `UdpV4 in
  Eio.Net.send sock ~dst [ query_buf ];
  let resp_buf = Cstruct.create 4096 in
  match Eio.Time.with_timeout clock 2.0 (fun () -> Ok (Eio.Net.recv sock resp_buf)) with
  | Ok (_addr, len) -> Some (Cstruct.sub resp_buf 0 len)
  | Error `Timeout ->
    Logs.warn (fun m -> m "Upstream timeout");
    None
;;

let name s = Domain_name.(host_exn (of_string_exn s))
