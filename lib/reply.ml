open Core

module Packet = struct
  type t = Cstruct.t

  let version = 1

  [%%cstruct
    type t =
      { _iphdr : uint8_t [@len 20]
      ; source : uint16_t
      ; dest : uint16_t
      ; len : uint16_t
      ; _check : uint16_t
      ; version : uint8_t
      ; hst_key : uint8_t [@len 32]
      ; dest_key : uint8_t [@len 32]
      ; rsrvd : uint8_t [@len 32]
      }
    [@@big_endian]]

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

  let create ?(source = 0) ?(dest_port = 0) ~hst_key ~dest_key () =
    Cstruct.create sizeof_t
    |> fun cs ->
    set_t_source cs source;
    cs
    |> fun cs ->
    set_t_dest cs dest_port;
    cs
    |> fun cs ->
    set_t_len cs sizeof_t;
    cs
    |> fun cs ->
    set_t_version cs version;
    cs
    |> fun cs ->
    let dest_key = Wglib.Wgapi.Key.to_string dest_key in
    set_t_dest_key dest_key 0 cs;
    cs
    |> fun cs ->
    let hst_key = Wglib.Wgapi.Key.to_string hst_key in
    set_t_hst_key hst_key 0 cs;
    cs
  ;;
end
