open Wireguard

let af_local = 1
let af_inet = 2
let af_inet6 = 10

module Key = struct
  open Ctypes

  type t = Unsigned.uchar Ctypes_static.carray

  let of_array arr =
    assert (Array.length arr = 32);
    let key = CArray.make Ctypes_static.uchar 32 in
    let () = Array.iteri (fun i c -> CArray.set key i c) arr in
    key
  ;;

  let generate_private_key () =
    let key = CArray.make Ctypes_static.uchar 32 in
    let () = wg_generate_private_key (CArray.start key) in
    key
  ;;

  let generate_public_key private_key =
    let public_key = CArray.make Ctypes_static.uchar 32 in
    let () =
      wg_generate_public_key (CArray.start public_key) (CArray.start private_key)
    in
    public_key
  ;;

  let generate_preshared_key () =
    let key = CArray.make Ctypes_static.uchar 32 in
    let () = wg_generate_preshared_key (CArray.start key) in
    key
  ;;

  let to_base64_string (key : t) =
    let base64 = CArray.make Ctypes_static.char 44 in
    let () = wg_key_to_base64 (CArray.start base64) (CArray.start key) in
    Ctypes.string_from_ptr
      (Ctypes.CArray.start base64)
      ~length:(Ctypes.CArray.length base64)
  ;;

  let of_base64_string (key_string : string) =
    let base64 = CArray.of_string key_string in
    assert (CArray.length base64 = 45);
    let key = CArray.make Ctypes_static.uchar 32 in
    let err = wg_key_from_base64 (CArray.start key) (CArray.start base64) in
    match err with
    | 0 -> Ok key
    | _ -> Error "Failed to convert string to key"
  ;;

  let to_string (key : t) =
    let char_ptr = Ctypes.coerce (ptr uchar) (ptr char) (CArray.start key) in
    string_from_ptr char_ptr ~length:(CArray.length key)
  ;;

  let of_string (s : string) : t =
    let len = String.length s in
    let arr = CArray.make uchar len in
    for i = 0 to len - 1 do
      CArray.set arr i (Unsigned.UChar.of_int (Char.code s.[i]))
    done;
    arr
  ;;
end

module Allowed_ip = struct
  open Ctypes
  module Ip = Ipaddr

  type t =
    { ip : Ip.t
    ; cidr : Unsigned.UInt8.t
    }

  let to_wg_allowed_ip allowed_ip =
    let family =
      match allowed_ip.ip with
      | Ip.V4 _ -> af_inet
      | Ip.V6 _ -> af_inet6
    in
    let callowed_ip = make Wg_peer.AllowedIp.wg_allowedip in
    setf callowed_ip Wg_peer.AllowedIp.family (Unsigned.UInt16.of_int family);
    setf callowed_ip Wg_peer.AllowedIp.cidr allowed_ip.cidr;
    (* Set the ip of the allowed ip c struct *)
    let () =
      match allowed_ip.ip with
      | Ip.V4 ip ->
        let addr = make Wg_peer.AllowedIp.in_addr in
        (* Reverse the octets of the ip *)
        (* TODO: figure out which way to flip oc tects is faster *)
        let ip_octets = Ip.V4.to_octets ip |> Base.String.to_array in
        let ip_uint32 =
          Base.Array.fold_right
            ~init:Unsigned.UInt32.zero
            ~f:(fun c (acc : Unsigned.UInt32.t) ->
              Unsigned.UInt32.logor
                (Unsigned.UInt32.shift_left acc 8)
                (Unsigned.UInt32.of_int (Base.Char.to_int c)))
            ip_octets
        in
        (* let ip_uint32 = *)
        (*   Ip.V4.to_octets ip |> Base.String.to_list_rev |> Base.String.of_list *)
        (* |> Ip.V4.of_octets_exn *)
        (* in *)
        setf addr Wg_peer.AllowedIp.s_addr ip_uint32;
        let ip = make Wg_peer.AllowedIp.ip_union in
        setf ip Wg_peer.AllowedIp.ip4 addr;
        setf callowed_ip Wg_peer.AllowedIp.ip ip
      | Ip.V6 ip ->
        let addr = make Wg_peer.AllowedIp.in6_addr in
        let ip_buf = Buffer.create 16 in
        Ip.V6.to_buffer ip_buf ip;
        Array.iteri
          (fun i c ->
             setf addr c (Buffer.nth ip_buf i |> Base.Char.to_int |> Unsigned.UChar.of_int))
          Wg_peer.AllowedIp.s6_addr;
        let ip = make Wg_peer.AllowedIp.ip_union in
        setf ip Wg_peer.AllowedIp.ip6 addr;
        setf callowed_ip Wg_peer.AllowedIp.ip ip
    in
    callowed_ip
  ;;

  let of_wg_allowed_ip allowed_ip : t =
    let allowed_ip = !@allowed_ip in
    let family = getf allowed_ip Wg_peer.AllowedIp.family |> Unsigned.UInt16.to_int in
    let cidr = getf allowed_ip Wg_peer.AllowedIp.cidr in
    let ip_union = getf allowed_ip Wg_peer.AllowedIp.ip in
    let ip : Ip.t =
      match family with
      | x when x == af_inet ->
        let addr = getf ip_union Wg_peer.AllowedIp.ip4 in
        let ip = getf addr Wg_peer.AllowedIp.s_addr |> Unsigned.UInt32.to_int32 in
        Ip.V4 (Ip.V4.of_int32 ip)
      | x when x == af_inet6 ->
        let addr = getf ip_union Wg_peer.AllowedIp.ip6 in
        let ip_buf = Buffer.create 16 in
        Array.iter
          (fun c ->
             Buffer.add_char
               ip_buf
               (getf addr c |> Unsigned.UChar.to_int |> Base.Char.of_int_exn))
          Wg_peer.AllowedIp.s6_addr;
        let ip = Ip.V6.of_octets_exn (ip_buf |> Buffer.to_seq |> String.of_seq) in
        Ip.V6 ip
      | x -> failwith ("Invalid family: " ^ (x |> Int.to_string))
    in
    { ip; cidr }
  ;;

  let set_next_allowedip allowed_ip next =
    setf allowed_ip Wg_peer.AllowedIp.next_allowedip next
  ;;

  (** [allowed_ips_of_list] [allowed_ip] takes a list ip allowed ips zips them together into a linked list and returns the first an last pointer *)
  let allowed_ips_of_list (allowed_ips : t list) =
    let allowed_ips = List.map to_wg_allowed_ip allowed_ips in
    let rec loop = function
      | [] -> ()
      | [ x ] -> set_next_allowedip x None
      | x :: y :: xs ->
        set_next_allowedip x (Some (addr y));
        loop (y :: xs)
    in
    loop allowed_ips;
    let first = List.hd allowed_ips |> addr in
    let last = Base.List.last_exn allowed_ips |> addr in
    first, last
  ;;

  let list_of_first_last first last =
    let rec loop acc current =
      if current == last
      then acc
      else (
        let next = getf !@current Wg_peer.AllowedIp.next_allowedip in
        match next with
        | None -> acc
        | Some next -> loop (current :: acc) next)
    in
    loop [] first |> List.map of_wg_allowed_ip
  ;;
end

module Endpoint = struct
  open Ctypes

  (* TODO: add support for unix sockets *)
  type t =
    { addr : [ `V4 of Ipaddr.V4.t | `V6 of Ipaddr.V6.t ]
    ; port : int
    }
  (* Unix.ADDR_UNIX *)

  let to_wg_endpoint e =
    (* Note: high and low byte of port are swapped so need to be swapped here*)
    let port = Unsigned.UInt16.of_int e.port in
    let port =
      Unsigned.UInt16.logor
        (Unsigned.UInt16.shift_left port 8)
        (Unsigned.UInt16.shift_right port 8)
    in
    let cendpoint = make Wg_endpoint.wg_endpoint in
    match e.addr with
    | `V4 addr ->
      let caddr = make Socket.Sockaddr_in.sockaddr_in in
      setf caddr Socket.Sockaddr_in.sin_family (Unsigned.UInt16.of_int af_inet);
      setf
        caddr
        Socket.Sockaddr_in.sin_addr
        (Ipaddr.V4.to_int32 addr |> Unsigned.UInt32.of_int32);
      setf caddr Socket.Sockaddr_in.sin_port port;
      setf cendpoint Wg_endpoint.addr4 caddr;
      cendpoint
    | `V6 addr ->
      let caddr = make Socket.Sockaddr_in6.sockaddr_in6 in
      setf caddr Socket.Sockaddr_in6.sin6_family (Unsigned.UInt16.of_int af_inet6);
      setf caddr Socket.Sockaddr_in6.sin6_port port;
      let ip_buf = Buffer.create 16 in
      Ipaddr.V6.to_buffer ip_buf addr;
      Array.iteri
        (fun i c ->
           setf caddr c (Buffer.nth ip_buf i |> Base.Char.to_int |> Unsigned.UInt8.of_int))
        Socket.Sockaddr_in6.sin6_addr;
      setf cendpoint Wg_endpoint.addr6 caddr;
      cendpoint
  ;;

  let of_wg_endpoint e =
    let family =
      getf (getf e Wg_endpoint.addr) Socket.Sockaddr.sa_family |> Unsigned.UInt16.to_int
    in
    match family with
    | 0 -> None
    | x when x == af_local ->
      let addr = getf e Wg_endpoint.addr in
      let _sa_data = Array.map (fun c -> getf addr c) Socket.Sockaddr.sa_data in
      (* TODO: implent local socket addr *)
      failwith "Not implemented"
    | x when x == af_inet ->
      let addr = getf e Wg_endpoint.addr4 in
      let port = getf addr Socket.Sockaddr_in.sin_port |> Unsigned.UInt16.to_int in
      let addr =
        getf addr Socket.Sockaddr_in.sin_addr
        |> Unsigned.UInt32.to_int32
        |> Ipaddr.V4.of_int32
      in
      Some { addr = `V4 addr; port }
    | x when x == af_inet6 ->
      let addr = getf e Wg_endpoint.addr6 in
      let port = getf addr Socket.Sockaddr_in6.sin6_port |> Unsigned.UInt16.to_int in
      let addr = Array.map (fun c -> getf addr c) Socket.Sockaddr_in6.sin6_addr in
      let addr =
        Ipaddr.V6.of_octets_exn
          (Array.map Unsigned.UInt8.to_int addr
           |> Array.map Char.chr
           |> Array.to_list
           |> Base.String.of_list)
      in
      Some { addr = `V6 addr; port }
    | x -> failwith ("Invalid family: " ^ (x |> Int.to_string))
  ;;
end

module Peer = struct
  open Ctypes

  (* WGPEER_REMOVE_ME = 1U << 0,
     WGPEER_REPLACE_ALLOWEDIPS = 1U << 1,
     WGPEER_HAS_PUBLIC_KEY = 1U << 2,
     WGPEER_HAS_PRESHARED_KEY = 1U << 3,
     WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4 *)
  type t =
    { public_key : Key.t Option.t
    ; preshared_key : Key.t Option.t
    ; endpoint : Endpoint.t Option.t
    ; last_handshake_time : Float.t
    ; rx_bytes : int
    ; tx_bytes : int
    ; persistent_keepalive_interval : int Option.t
    ; allowed_ips : Allowed_ip.t list
    }

  let create
        ?(public_key : Key.t option)
        ?(preshared_key : Key.t option)
        ?(endpoint : Endpoint.t option)
        ?(persistent_keepalive_interval : int option)
        ?allowed_ips
        ()
    =
    { public_key
    ; preshared_key
    ; endpoint
    ; last_handshake_time = 0.0
    ; rx_bytes = 0
    ; tx_bytes = 0
    ; persistent_keepalive_interval
    ; allowed_ips = Option.value ~default:[] allowed_ips
    }
  ;;

  (* Note: does this need to be a pointer? *)
  type s = Wg_peer.wg_peer structure
  type p = s ptr

  let to_wg_peer peer : s =
    let flags = ref Wg_peer.Wg_peer_flags.wgpeer_replace_allowedips in
    let cpeer = make Wg_peer.wg_peer in
    (* Set public key *)
    let () =
      match peer.public_key with
      | None -> ()
      | Some key ->
        let () =
          CArray.iteri
            (fun i c -> Ctypes.setf cpeer (Array.get Wireguard.Wg_peer.public_key i) c)
            key
        in
        flags := !flags lor Wg_peer.Wg_peer_flags.wgpeer_has_public_key
    in
    (* Set preshared key *)
    let () =
      match peer.preshared_key with
      | None -> ()
      | Some key ->
        let () =
          CArray.iteri
            (fun i c -> Ctypes.setf cpeer (Array.get Wireguard.Wg_peer.preshared_key i) c)
            key
        in
        flags := !flags lor Wg_peer.Wg_peer_flags.wgpeer_has_preshared_key
    in
    (* Set persistent_keepalive_interval *)
    let () =
      match peer.persistent_keepalive_interval with
      | None -> ()
      | Some interval ->
        let () =
          setf
            cpeer
            Wg_peer.persistent_keepalive_interval
            (Unsigned.UInt16.of_int interval)
        in
        flags := !flags lor Wg_peer.Wg_peer_flags.wgpeer_has_persistent_keepalive_interval
    in
    (* Set allowed ips *)
    let () =
      match List.is_empty peer.allowed_ips with
      | true -> ()
      | false ->
        let first_allowedip, last_allowedip =
          Allowed_ip.allowed_ips_of_list peer.allowed_ips
        in
        let () = setf cpeer Wg_peer.first_allowedip (Some first_allowedip) in
        let () = setf cpeer Wg_peer.last_allowedip (Some last_allowedip) in
        flags := !flags lor Wg_peer.Wg_peer_flags.wgpeer_replace_allowedips
    in
    (* Set flags *)
    setf cpeer Wg_peer.flags (Unsigned.UInt32.of_int !flags);
    (* Set endpoint *)
    let () =
      match peer.endpoint with
      | None -> ()
      | Some endpoint ->
        let cendpoint = Endpoint.to_wg_endpoint endpoint in
        setf cpeer Wg_peer.endpoint cendpoint
    in
    (* let () = failwith "Not implemented" in *)
    cpeer
  ;;

  let of_wg_peer (peer : s) : t =
    let flags = getf peer Wg_peer.flags |> Unsigned.UInt32.to_int in
    let public_key : Key.t Option.t =
      match flags land Wg_peer.Wg_peer_flags.wgpeer_has_public_key with
      | 0 -> None
      | _ -> Some (Array.map (fun c -> getf peer c) Wg_peer.public_key |> Key.of_array)
    in
    let preshared_key : Key.t Option.t =
      match flags land Wg_peer.Wg_peer_flags.wgpeer_has_preshared_key with
      | 0 -> None
      | _ -> Some (Array.map (fun c -> getf peer c) Wg_peer.preshared_key |> Key.of_array)
    in
    let persistent_keepalive_interval =
      match flags land Wg_peer.Wg_peer_flags.wgpeer_has_persistent_keepalive_interval with
      | 0 -> None
      | _ ->
        Some (getf peer Wg_peer.persistent_keepalive_interval |> Unsigned.UInt16.to_int)
    in
    let last_handshake_time = getf peer Wg_peer.last_handshake_time in
    let last_handshake_time_sec =
      getf last_handshake_time TimeSpec64.tv_sec |> Int64.to_int
    in
    let last_handshake_time_nsec =
      getf last_handshake_time TimeSpec64.tv_nsec |> Int64.to_int
    in
    let last_handshake_time =
      Float.of_int last_handshake_time_sec
      +. (Float.of_int last_handshake_time_nsec /. 1_000_000_000.)
    in
    let rx_bytes = getf peer Wg_peer.rx_bytes |> Unsigned.UInt64.to_int in
    let tx_bytes = getf peer Wg_peer.tx_bytes |> Unsigned.UInt64.to_int in
    let first_allowedip = getf peer Wg_peer.first_allowedip in
    let last_allowedip = getf peer Wg_peer.last_allowedip in
    let allowed_ips =
      match first_allowedip, last_allowedip with
      | Some first, Some last -> Allowed_ip.list_of_first_last first last
      | _, _ -> []
    in
    let endpoint = getf peer Wg_peer.endpoint |> Endpoint.of_wg_endpoint in
    { public_key
    ; preshared_key
    ; endpoint
    ; last_handshake_time
    ; rx_bytes
    ; tx_bytes
    ; persistent_keepalive_interval
    ; allowed_ips
    }
  ;;

  (* let list_of_first_last (start : p) (stop : p) : t list = *)
  (*   let rec loop acc current : s list = *)
  (*     if current == stop then !@current :: acc *)
  (*     else *)
  (*       let next = getf !@current Wg_peer.next_peer in *)
  (*       match next with *)
  (*       | None -> acc *)
  (*       | Some next -> loop (!@current :: acc) next *)
  (*   in *)
  (*   loop [] start |> List.map of_wg_peer *)

  let list_of_first_last (start : p) (_stop : p) : t list =
    let rec loop acc current : s list =
      let next = getf !@current Wg_peer.next_peer in
      match next with
      | None -> !@current :: acc
      | Some next -> loop (!@current :: acc) next
    in
    loop [] start |> List.map of_wg_peer
  ;;

  let set_next_peer (peer : s) next = setf peer Wg_peer.next_peer next

  let s_list_of_list (peers : t list) =
    let cpeers = List.map to_wg_peer peers in
    let rec loop = function
      | [] -> ()
      | [ x ] -> set_next_peer x None
      | x :: y :: xs ->
        set_next_peer x (Some (addr y));
        loop (y :: xs)
    in
    loop cpeers;
    cpeers
  ;;

  let first_last_of_list (peers : t list) =
    match List.is_empty peers with
    | true -> None, None
    | false ->
      let cpeers = s_list_of_list peers in
      let first = Base.List.hd_exn cpeers |> addr in
      let last = Base.List.last_exn cpeers |> addr in
      Some first, Some last
  ;;
end

module Interface = struct
  open Ctypes

  (* typedef struct wg_device { *)
  (* 	char name[IFNAMSIZ]; *)
  (* 	uint32_t ifindex; *)
  (* 	enum wg_device_flags flags; *)
  (* 	wg_key public_key; *)
  (* 	wg_key private_key; *)
  (* 	uint32_t fwmark; *)
  (* 	uint16_t listen_port; *)
  (* 	struct wg_peer *first_peer, *last_peer; *)
  (* } wg_device; *)

  type t =
    { name : string
    ; ifindex : int
    ; public_key : Key.t Option.t
    ; private_key : Key.t Option.t
    ; fwmark : int Option.t
    ; listen_port : int Option.t
    ; peers : Peer.t List.t
    }

  let create
        ~name
        ?(public_key : Key.t option)
        ?(private_key : Key.t option)
        ?(fwmark : int option)
        ?(listen_port : int option)
        ?peers
        ()
    =
    let _ = Wireguard.wg_add_device name in
    { name
    ; ifindex = -1
    ; public_key
    ; private_key
    ; fwmark
    ; listen_port
    ; peers = Option.value ~default:[] peers
    }
  ;;

  let to_wg_device device =
    let flags = ref Wg_device.Wg_device_flags.wgdevice_replace_peers in
    let cdevice = make Wg_device.wg_device in
    let name_arr = Base.String.to_array device.name in
    (* Set name *)
    let () =
      Base.Array.iteri
        ~f:(fun i c -> setf cdevice (Array.get Wireguard.Wg_device.name i) c)
        name_arr
    in
    (* Set port *)
    let () =
      match device.listen_port with
      | None -> ()
      | Some port ->
        let () = setf cdevice Wg_device.listen_port (Unsigned.UInt16.of_int port) in
        flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_listen_port
    in
    (* Set public key *)
    let () =
      match device.public_key with
      | None -> ()
      | Some key ->
        let () =
          CArray.iteri
            (fun i c ->
               Ctypes.setf cdevice (Array.get Wireguard.Wg_device.public_key i) c)
            key
        in
        flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_public_key
    in
    (* Set Private key *)
    let () =
      match device.private_key with
      | None -> ()
      | Some key ->
        let () =
          CArray.iteri
            (fun i c ->
               Ctypes.setf cdevice (Array.get Wireguard.Wg_device.private_key i) c)
            key
        in
        flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_private_key
    in
    (* Set fwmark *)
    let () =
      match device.fwmark with
      | None -> ()
      | Some fwmark ->
        let () = setf cdevice Wg_device.fwmark (Unsigned.UInt32.of_int fwmark) in
        flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_fwmark
    in
    (* Set flags *)
    let () = setf cdevice Wg_device.flags (Unsigned.UInt32.of_int !flags) in
    (* set first and last peer *)
    let first_peer, last_peer = Peer.first_last_of_list device.peers in
    let () = setf cdevice Wg_device.first_peer first_peer in
    let () = setf cdevice Wg_device.last_peer last_peer in
    cdevice
  ;;

  let of_wg_device cdevice =
    let device =
      { name = ""
      ; ifindex = 0
      ; public_key = None
      ; private_key = None
      ; fwmark = None
      ; listen_port = None
      ; peers = []
      }
    in
    let flags = getf cdevice Wg_device.flags |> Unsigned.UInt32.to_int in
    (* Listen port *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_listen_port with
      | 0 -> device
      | _ ->
        { device with
          listen_port = Some (getf cdevice Wg_device.listen_port |> Unsigned.UInt16.to_int)
        }
    in
    (* Public key *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_public_key with
      | 0 -> device
      | _ ->
        let public_key = Array.map (fun c -> getf cdevice c) Wg_device.public_key in
        { device with public_key = Some (Key.of_array public_key) }
    in
    (* private key *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_private_key with
      | 0 -> device
      | _ ->
        let private_key = Array.map (fun c -> getf cdevice c) Wg_device.private_key in
        { device with private_key = Some (Key.of_array private_key) }
    in
    (* fwmark *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_fwmark with
      | 0 -> device
      | _ ->
        { device with
          fwmark = Some (getf cdevice Wg_device.fwmark |> Unsigned.UInt32.to_int)
        }
    in
    (* Name *)
    let device =
      let name = Array.map (fun c -> getf cdevice c) Wg_device.name in
      { device with name = Base.String.of_array name }
    in
    (* Ifindex *)
    let device =
      let ifindex = getf cdevice Wg_device.ifindex |> Unsigned.UInt32.to_int in
      { device with ifindex }
    in
    let first_peer = getf cdevice Wg_device.first_peer in
    let last_peer = getf cdevice Wg_device.last_peer in
    match first_peer, last_peer with
    | Some first, Some last -> { device with peers = Peer.list_of_first_last first last }
    | _, None -> device
    | None, _ -> device
  ;;

  let get_device name =
    let cdevice = make Wg_device.wg_device in
    let cdevice = allocate (ptr Wg_device.wg_device) (addr cdevice) in
    let res = wg_get_device cdevice name in
    match res with
    | 0 -> Ok (of_wg_device !@(!@cdevice))
    | _ -> Error "Failed to get device"
  ;;

  (* Note: when sending peers they need to be stored in stable memory (bigarray, CArray, malloc, Ctypes.allocate) I assume Ctypes.make *)

  module DeviceError = struct
    (** EPERM		 1	/* Operation not permitted */
        ENOENT		 2	/* No such file or directory */
        ESRCH		 3	/* No such process */
        EINTR		 4	/* Interrupted system call */
        EIO		     5	/* I/O error */
        ENXIO		 6	/* No such device or address */
        E2BIG		 7	/* Argument list too long */
        ENOEXEC		 8	/* Exec format error */
        EBADF		 9	/* Bad file number */
        ECHILD		10	/* No child processes */
        EAGAIN		11	/* Try again */
        ENOMEM		12	/* Out of memory */
        EACCES		13	/* Permission denied */
        EFAULT		14	/* Bad address */
        ENOTBLK		15	/* Block device required */
        EBUSY		16	/* Device or resource busy */
        EEXIST		17	/* File exists */
        EXDEV		18	/* Cross-device link */
        ENODEV		19	/* No such device */
        ENOTDIR		20	/* Not a directory */
        EISDIR		21	/* Is a directory */
        EINVAL		22	/* Invalid argument */
        ENFILE		23	/* File table overflow */
        EMFILE		24	/* Too many open files */
        ENOTTY		25	/* Not a typewriter */
        ETXTBSY		26	/* Text file busy */
        EFBIG		27	/* File too large */
        ENOSPC		28	/* No space left on device */
        ESPIPE		29	/* Illegal seek */
        EROFS		30	/* Read-only file system */
        EMLINK		31	/* Too many links */
        EPIPE		32	/* Broken pipe */
        EDOM		33	/* Math argument out of domain of func */
        ERANGE		34	/* Math result not representable */ *)
    type t =
      | EPERM
      | ENOENT
      | ESRCH
      | EINTR
      | EIO
      | ENXIO
      | E2BIG
      | ENOEXEC
      | EBADF
      | ECHILD
      | EAGAIN
      | ENOMEM
      | EACCES
      | EFAULT
      | ENOTBLK
      | EBUSY
      | EEXIST
      | EXDEV
      | ENODEV
      | ENOTDIR
      | EISDIR
      | EINVAL
      | ENFILE
      | EMFILE
      | ENOTTY
      | ETXTBSY
      | EFBIG
      | ENOSPC
      | ESPIPE
      | EROFS
      | EMLINK
      | EPIPE
      | EDOM
      | ERANGE

    let to_string e =
      match e with
      | EPERM -> "Operation not permitted"
      | ENOENT -> "No such file or directory"
      | ESRCH -> "No such process"
      | EINTR -> "Interrupted system call"
      | EIO -> "I/O error"
      | ENXIO -> "No such device or address"
      | E2BIG -> "Argument list too long"
      | ENOEXEC -> "Exec format error"
      | EBADF -> "Bad file number"
      | ECHILD -> "No child processes"
      | EAGAIN -> "Try again"
      | ENOMEM -> "Out of memory"
      | EACCES -> "Permission denied"
      | EFAULT -> "Bad address"
      | ENOTBLK -> "Block device required"
      | EBUSY -> "Device or resource busy"
      | EEXIST -> "File exists"
      | EXDEV -> "Cross-device link"
      | ENODEV -> "No such device"
      | ENOTDIR -> "Not a directory"
      | EISDIR -> "Is a directory"
      | EINVAL -> "Invalid argument"
      | ENFILE -> "File table overflow"
      | EMFILE -> "Too many open files"
      | ENOTTY -> "Not a typewriter"
      | ETXTBSY -> "Text file busy"
      | EFBIG -> "File too large"
      | ENOSPC -> "No space left on device"
      | ESPIPE -> "Illegal seek"
      | EROFS -> "Read-only file system"
      | EMLINK -> "Too many links"
      | EPIPE -> "Broken pipe"
      | EDOM -> "Math argument out of domain of func"
      | ERANGE -> "Math result not representable"
    ;;

    let of_int i =
      match i * -1 with
      | 0 -> Ok ()
      | 1 -> Error EPERM
      | 2 -> Error ENOENT
      | 3 -> Error ESRCH
      | 4 -> Error EINTR
      | 5 -> Error EIO
      | 6 -> Error ENXIO
      | 7 -> Error E2BIG
      | 8 -> Error ENOEXEC
      | 9 -> Error EBADF
      | 10 -> Error ECHILD
      | 11 -> Error EAGAIN
      | 12 -> Error ENOMEM
      | 13 -> Error EACCES
      | 14 -> Error EFAULT
      | 15 -> Error ENOTBLK
      | 16 -> Error EBUSY
      | 17 -> Error EEXIST
      | 18 -> Error EXDEV
      | 19 -> Error ENODEV
      | 20 -> Error ENOTDIR
      | 21 -> Error EISDIR
      | 22 -> Error EINVAL
      | 23 -> Error ENFILE
      | 24 -> Error EMFILE
      | 25 -> Error ENOTTY
      | 26 -> Error ETXTBSY
      | 27 -> Error EFBIG
      | 28 -> Error ENOSPC
      | 29 -> Error ESPIPE
      | 30 -> Error EROFS
      | 31 -> Error EMLINK
      | 32 -> Error EPIPE
      | 33 -> Error EDOM
      | 34 -> Error ERANGE
      | e -> failwith ("Unknown error: " ^ (e |> Int.to_string))
    ;;
  end

  (* BUG: Cant add 90+ devices at once *)
  let set_device device =
    let cdevice = to_wg_device device in
    let res = wg_set_device (addr cdevice) in
    DeviceError.of_int res
  ;;

  (* Wireguard.Wg_device.Wg_device_flags.wgdevice_replace_peers <- Used to replace peers instead of adding them *)
  (* Set device without the public key flag *)
  let add_peers device peers =
    let device = { device with peers } in
    let cdevice = to_wg_device device in
    setf cdevice Wg_device.flags (Unsigned.UInt32.of_int 0);
    let res = wg_set_device (addr cdevice) in
    DeviceError.of_int res
  ;;

  let set_peers device peers =
    let device = { device with peers } in
    let cdevice = to_wg_device device in
    setf
      cdevice
      Wg_device.flags
      (Unsigned.UInt32.of_int Wg_device.Wg_device_flags.wgdevice_replace_peers);
    wg_set_device (addr cdevice) |> DeviceError.of_int
  ;;

  let configure_peers _peers = failwith "Not implemented"

  let remove_peers device peers =
    assert (not (List.is_empty peers));
    let peers = Peer.s_list_of_list peers in
    let () =
      List.iter
        (fun p ->
           setf
             p
             Wg_peer.flags
             (Wg_peer.Wg_peer_flags.wgpeer_remove_me |> Unsigned.UInt32.of_int))
        peers
    in
    let cdevice = to_wg_device device in
    setf cdevice Wg_device.flags (Unsigned.UInt32.of_int 0);
    let first_peer, last_peer = Base.(List.hd_exn peers, List.last_exn peers) in
    setf cdevice Wg_device.first_peer (Some (addr first_peer));
    setf cdevice Wg_device.last_peer (Some (addr last_peer));
    wg_set_device (addr cdevice) |> DeviceError.of_int
  ;;
end
