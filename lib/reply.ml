open Core

module Packet = struct
  type t = Cstruct.t

  let version = 1

  (* TODO: Handle ip v4 and v6  with a flag to reply with which is used  *)
  [%%cstruct
    type t =
      { _iphdr : uint8_t [@len 20]
      ; source : uint16_t
      ; dest : uint16_t
      ; len : uint16_t
      ; _check : uint16_t
      ; version : uint8_t
      ; found : uint8_t
      ; v4v6 : uint8_t
      ; addr : uint8_t [@len 16]
      ; port : uint16_t
      ; rsrvd : uint8_t [@len 32]
      }
    [@@big_endian]]

  [%%cenum
    type found =
      | Found
      | Not_Found
    [@@uint8_t]]

  [%%cenum
    type v4v6 =
      | V4
      | V6
    [@@uint8_t]]

  let iphdr_len = 20
  let udphdr_len = 8
  let payload_size = sizeof_t - udphdr_len - iphdr_len
  let sexp_of_t = Cstruct_sexp.sexp_of_t
  let t_of_sexp = Cstruct_sexp.t_of_sexp

  let of_bytes ?(hdr = false) b =
    let expected_len = if hdr then sizeof_t else payload_size in
    if Bytes.length b < expected_len
    then
      invalid_argf
        "RawUdpSock.Packet.of_bytes expected at least %d bytes, got %d"
        expected_len
        (Bytes.length b)
        ()
    else if hdr
    then Cstruct.of_bytes ~len:sizeof_t b
    else (
      let cs = Cstruct.create sizeof_t in
      Cstruct.blit_from_bytes b 0 cs (udphdr_len + iphdr_len) payload_size;
      cs)
  ;;

  let to_bytes ?(hdr = false) t =
    Cstruct.to_bytes
      ~off:(if hdr then 0 else udphdr_len + iphdr_len)
      ~len:(if hdr then sizeof_t else payload_size)
      t
  ;;

  let to_cstruct ?(hdr = false) t = to_bytes ~hdr t |> Cstruct.of_bytes

  let create_buffer ?(hdr = false) () =
    if hdr then Cstruct.create sizeof_t |> Cstruct.to_bytes else Bytes.create payload_size
  ;;

  let create ?(source = 0) ?(dest_port = 0) ~found ~(addr : Ipaddr.t) ~port () =
    let cs = Cstruct.create sizeof_t in
    set_t_source cs source;
    set_t_dest cs dest_port;
    set_t_len cs sizeof_t;
    set_t_version cs version;
    set_t_found cs (found_to_int found);
    set_t_port cs port;
    (match addr with
     | Ipaddr.V4 ip ->
       let ipv4_bytes = Ipaddr.V4.to_octets ip in
       let padded_endpoint = ipv4_bytes ^ String.make 12 '\000' in
       set_t_addr padded_endpoint 0 cs;
       set_t_v4v6 cs (v4v6_to_int V4)
     | Ipaddr.V6 _ ->
       set_t_addr (Ipaddr.to_octets addr) 0 cs;
       set_t_v4v6 cs (v4v6_to_int V6));
    cs
  ;;

  (* TODO: replace exeption *)
  let get_t_addr t =
    let addr = copy_t_addr t in
    match get_t_v4v6 t |> int_to_v4v6 with
    | None -> None
    | Some V6 ->
      let addr = Ipaddr.of_octets_exn addr in
      Some addr
    | Some V4 ->
      let addr = Ipaddr.of_octets_exn (String.subo ~len:4 addr) in
      Some addr
  ;;
end
