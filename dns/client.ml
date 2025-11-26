(* DNS Client Library using Dns_client *)
(* TODO: setup search in resolv.conf *)

module Client = struct
  type +'a io = 'a

  type stack =
    { net : Eio_unix.Net.t
    ; sw : Eio.Switch.t
    ; clock : float Eio.Time.clock_ty Eio.Resource.t
    }

  type io_addr = Ipaddr.t * int

  type t =
    { net : Eio_unix.Net.t
    ; nameservers : Dns.proto * io_addr list
    ; timeout_ns : int64
    ; sw : Eio.Switch.t
    ; clock : float Eio.Time.clock_ty Eio.Resource.t
    }

  type context =
    { socket : [ `Generic ] Eio.Net.datagram_socket_ty Eio.Resource.t
    ; addr : Eio.Net.Sockaddr.datagram
    ; timeout_s : float
    ; clock : float Eio.Time.clock_ty Eio.Resource.t
    }

  let create ?(nameservers = `Udp, []) ~timeout (stack : stack) =
    { net = stack.net
    ; nameservers
    ; timeout_ns = timeout
    ; sw = stack.sw
    ; clock = stack.clock
    }
  ;;

  let nameservers t = t.nameservers
  let rng n = Mirage_crypto_rng.generate n
  let clock () = Mtime_clock.now () |> Mtime.to_uint64_ns

  let connect t =
    let proto, addrs = t.nameservers in
    match addrs with
    | [] -> Error (`Msg "No nameservers configured")
    | (ip, port) :: _ ->
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
         let socket = Eio.Net.datagram_socket ~sw:t.sw t.net bind_addr in
         Ok
           ( proto
           , { socket :> [ `Generic ] Eio.Net.datagram_socket_ty Eio.Resource.t
             ; addr = dst_addr
             ; timeout_s =
                 Core.(Float.of_int64 t.timeout_ns /. (Int.pow 10 9 |> Int.to_float))
             ; clock = t.clock
             } )
       with
       | e -> Error (`Msg (Printexc.to_string e)))
  ;;

  let send_recv ctx msg =
    try
      let query_buf = Cstruct.of_string msg in
      Eio.Net.send ctx.socket ~dst:ctx.addr [ query_buf ];
      let resp_buf = Cstruct.create 512 in
      match
        Eio.Time.with_timeout ctx.clock ctx.timeout_s (fun () ->
          Ok (Eio.Net.recv ctx.socket resp_buf))
      with
      | Error `Timeout ->
        Logs.warn (fun m -> m "Upstream timeout");
        Error (`Msg "Upstream timeout")
      | Ok (_addr, recv_len) -> Ok (Cstruct.to_string (Cstruct.sub resp_buf 0 recv_len))
    with
    | e -> Error (`Msg (Printexc.to_string e))
  ;;

  let close _ctx = ()
  let bind x f = f x
  let lift x = x
end

module C = Dns_client.Make (Client)

(* Helper function to create a DNS client with proper types *)
let create_client
      ?nameservers
      ~(clock : float Eio.Time.clock_ty Eio.Resource.t)
      ~timeout
      ~sw
      ~(net : Eio_unix.Net.t)
      ()
  =
  let client = C.create ?nameservers ~timeout { net; sw; clock } in
  client
;;

(* TODO: *)
(* include C *)
