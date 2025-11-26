let eio_to_ipaddr (ip : Eio.Net.Ipaddr.v4v6) : Ipaddr.t =
  let str = Format.asprintf "%a" Eio.Net.Ipaddr.pp ip in
  Ipaddr.of_string_exn str
;;

let ipaddr_to_eio (ip : Ipaddr.t) : Eio.Net.Ipaddr.v4v6 =
  Eio.Net.Ipaddr.of_raw (Ipaddr.to_octets ip)
;;
