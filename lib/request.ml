open Core

module Packet = struct
  type t = Cstruct.t

  let version = 1

  [%%cstruct
    type t =
      { source : uint16_t
      ; dest : uint16_t
      ; len : uint16_t
      ; _check : uint16_t
      ; version : uint8_t
      ; timestamp : uint64
      ; mac : uint8_t [@len 16]
      ; hst_key : uint8_t [@len 32]
      ; dest_key : uint8_t [@len 32]
      }
    [@@big_endian]]

  (* TODO:check timestamp *)
  let udp_header_len = 8
  let payload_size = sizeof_t - udp_header_len
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
      Cstruct.blit_from_bytes b 0 cs udp_header_len payload_size;
      cs)
  ;;

  let create_buffer ?(hdr = false) () =
    if hdr then Cstruct.create sizeof_t |> Cstruct.to_bytes else Bytes.create payload_size
  ;;

  let gen_mac ~priv_key ~pub_key ~hst_key ~dest_key timestamp =
    let message = String.concat [ hst_key; dest_key; Int64.to_string timestamp ] in
    Crypto.gen_mac ~priv_key ~pub_key ~message
    |> Option.value_exn ~message:"Failed to generate mac"
  ;;

  let create ~source ~dest_port ~hst_key ~dest_key ~priv_key ~pub_key =
    let cs = Cstruct.create sizeof_t in
    set_t_source cs source;
    set_t_dest cs dest_port;
    set_t_len cs sizeof_t;
    set_t_version cs version;
    let dest_key = Wglib.Wgapi.Key.to_string dest_key in
    set_t_dest_key dest_key 0 cs;
    let hst_key = Wglib.Wgapi.Key.to_string hst_key in
    set_t_hst_key hst_key 0 cs;
    let timestamp = Core_unix.time () |> Int64.of_float in
    set_t_timestamp cs timestamp;
    let mac = gen_mac ~priv_key ~pub_key ~hst_key ~dest_key timestamp in
    set_t_mac mac 0 cs;
    cs
  ;;
end

module RawUdpSock = struct
  type t = Core_unix.File_descr.t

  let init () : t = Core_unix.socket ~domain:PF_INET ~kind:SOCK_RAW ~protocol:17 ()

  let send sock packet ~dest =
    Core_unix.sendto
      sock
      ~buf:(Cstruct.to_bytes packet)
      ~pos:0
      ~len:Packet.sizeof_t
      ~mode:[]
      ~addr:dest
  ;;
end
