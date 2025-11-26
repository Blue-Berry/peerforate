(* DNS Client Library using Dns_client *)

(* TODO: change to functor? https://mirage.github.io/ocaml-dns/dns-client/Dns_client/module-type-S/index.html *)
let name s = Domain_name.(host_exn (of_string_exn s))

(* Query for TXT records using Dns_client.Pure *)
let query_txt ~sw ~net ~dst ~clock domain_name =
  let open Dns in
  let domain = name domain_name in
  (* Use Dns_client.Pure.make_query to create a DNS query *)
  let rng = Mirage_crypto_rng.generate ?g:None in
  let query_str, _query_state =
    Dns_client.Pure.make_query rng `Udp `None domain Rr_map.Txt
  in
  (* Send query and receive response *)
  let query_buf = Cstruct.of_string query_str in
  match Utils.query ~sw ~net ~dst ~query_buf ~clock with
  | None -> Error `Query_failed
  | Some resp_buf ->
    (* Decode response *)
    (match Packet.decode (Cstruct.to_string resp_buf) with
     | Error e -> Error (`Decode_error e)
     | Ok response ->
       (* Extract TXT records from answer *)
       (match response.Packet.data with
        | `Answer (answer, _) ->
          let raw_domain = Domain_name.raw domain in
          (match Domain_name.Map.find_opt raw_domain answer with
           | Some rr_map ->
             (* Extract TXT records from the Rr_map *)
             (match Dns.Rr_map.find Rr_map.Txt rr_map with
              | Some (ttl, txt_set) ->
                let txt_records = Rr_map.Txt_set.elements txt_set in
                Ok (ttl, txt_records)
              | None -> Error `Wrong_record_type)
           | None -> Error `No_answer)
        | _ -> Error `Not_an_answer))
;;

(* Higher-level function to get TXT records as strings *)
let get_txt_records ~sw ~net ~dst ~clock domain_name =
  match query_txt ~sw ~net ~dst ~clock domain_name with
  | Ok (ttl, records) ->
    Logs.info (fun m ->
      m "TXT records for %s (TTL=%ld): %d records" domain_name ttl (List.length records));
    Ok records
  | Error e ->
    Logs.warn (fun m -> m "Failed to query TXT for %s" domain_name);
    Error e
;;

(* Example: Get encryption key from DNS TXT record *)
let get_key ~sw ~net ~dst ~clock =
  match get_txt_records ~sw ~net ~dst ~clock "key.vpn.local" with
  | Ok (key :: _) -> Some key
  | Ok [] -> None
  | Error _ -> None
;;

(* TODO: setup search in resolv.conf *)

module S = struct
  type +'a io = 'a
  type stack = Eio_unix.Net.t
  type io_addr = Ipaddr.t * int

  type t =
    { net : stack
    ; nameservers : Dns.proto * io_addr list
    ; timeout_ns : int64 [@warning "-69"]
    ; sw : Eio.Switch.t option ref
    }

  type context =
    { socket : [ `Generic ] Eio.Net.datagram_socket_ty Eio.Resource.t
    ; addr : Eio.Net.Sockaddr.datagram
    }

  let create ?(nameservers = `Udp, []) ~timeout stack =
    { net = stack; nameservers; timeout_ns = timeout; sw = ref None }
  ;;

  (* Helper to set the switch - call this from within an Eio context *)
  let set_switch t sw =
    t.sw := Some sw;
    t
  [@@warning "-32"]
  ;;

  let nameservers t = t.nameservers
  let rng n = Mirage_crypto_rng.generate n
  let clock () = Mtime_clock.now () |> Mtime.to_uint64_ns

  let connect t =
    let proto, addrs = t.nameservers in
    match !(t.sw), addrs with
    | None, _ ->
      Error
        (`Msg "No switch set. Call set_switch within an Eio context before using connect.")
    | _, [] -> Error (`Msg "No nameservers configured")
    | Some sw, (ip, port) :: _ ->
      (try
         (* Destination address for the DNS server *)
         let dst_addr =
           match ip with
           | Ipaddr.V4 ipv4 ->
             let octets = Ipaddr.V4.to_octets ipv4 in
             `Udp (Eio.Net.Ipaddr.of_raw octets, port)
           | Ipaddr.V6 ipv6 ->
             let octets = Ipaddr.V6.to_octets ipv6 in
             `Udp (Eio.Net.Ipaddr.of_raw octets, port)
         in
         (* Create socket bound to ephemeral port, not to the destination *)
         let bind_addr =
           match ip with
           | Ipaddr.V4 _ ->
             `Udp (Eio.Net.Ipaddr.V4.any, 0) (* Bind to 0.0.0.0:0 (ephemeral port) *)
           | Ipaddr.V6 _ -> `Udp (Eio.Net.Ipaddr.V6.any, 0)
           (* Bind to [::]:0 (ephemeral port) *)
         in
         let socket = Eio.Net.datagram_socket ~sw t.net bind_addr in
         Ok
           ( proto
           , { socket :> [ `Generic ] Eio.Net.datagram_socket_ty Eio.Resource.t
             ; addr = dst_addr
             } )
       with
       | e -> Error (`Msg (Printexc.to_string e)))
  ;;

  let send_recv ctx msg =
    try
      let query_buf = Cstruct.of_string msg in
      Eio.Net.send ctx.socket ~dst:ctx.addr [ query_buf ];
      let resp_buf = Cstruct.create 512 in
      let _addr, recv_len = Eio.Net.recv ctx.socket resp_buf in
      Ok (Cstruct.to_string (Cstruct.sub resp_buf 0 recv_len))
    with
    | e -> Error (`Msg (Printexc.to_string e))
  ;;

  let close _ctx = ()
  let bind x f = f x
  let lift x = x
end

module C = Dns_client.Make (S)

(* Helper function to create a DNS client with proper types *)
let create_client ?nameservers ~timeout ~sw (net : Eio_unix.Net.t) =
  let client = C.create ?nameservers ~timeout net in
  let _transport = C.transport client |> fun t -> S.set_switch t sw in
  client
;;
