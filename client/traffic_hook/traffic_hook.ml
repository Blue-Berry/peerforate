(* Traffic Hook - eBPF-based egress packet monitoring *)

open Ctypes
open Libbpf
open Libbpf_maps

type callback = dst_ip:Ipaddr.t -> timestamp:int64 -> unit

let packet_event : [ `Packet_event ] structure typ = structure "packet_event"
let ev_dst_ip = field packet_event "dst_ip" (array 16 uint8_t)
let ev_version = field packet_event "version" uint32_t
let _ = field packet_event "_pad" uint32_t (* padding *)
let ev_ts = field packet_event "ts" uint64_t
let () = seal packet_event

(* Find BPF object file *)
let find_bpf_object () =
  let candidates =
    [ Filename.concat (Filename.dirname Sys.executable_name) "packet_filter.bpf.o"
    ; "packet_filter.bpf.o"
    ; "client/traffic_hook/packet_filter.bpf.o"
    ]
  in
  match List.find_opt Sys.file_exists candidates with
  | Some path -> path
  | None -> failwith "Cannot find packet_filter.bpf.o"
;;

let ip_of_event ev =
  let version = getf ev ev_version |> Unsigned.UInt32.to_int in
  let bytes = getf ev ev_dst_ip in
  if version == 4
  then (
    (* IPv4: bytes 0-3 *)
    let b0 = Unsigned.UInt8.to_int (CArray.get bytes 0) in
    let b1 = Unsigned.UInt8.to_int (CArray.get bytes 1) in
    let b2 = Unsigned.UInt8.to_int (CArray.get bytes 2) in
    let b3 = Unsigned.UInt8.to_int (CArray.get bytes 3) in
    let ip =
      Int32.(
        logor
          (shift_left (of_int b0) 24)
          (logor
             (shift_left (of_int b1) 16)
             (logor (shift_left (of_int b2) 8) (of_int b3))))
    in
    Ipaddr.V4 (Ipaddr.V4.of_int32 ip))
  else (
    (* IPv6: all 16 bytes *)
    let s =
      String.init 16 (fun i -> Char.chr (Unsigned.UInt8.to_int (CArray.get bytes i)))
    in
    match Ipaddr.V6.of_octets s with
    | Ok v6 -> Ipaddr.V6 v6
    | Error _ -> failwith "Invalid IPv6 bytes from BPF")
;;

let get_ifindex ifname =
  let if_nametoindex = Foreign.foreign "if_nametoindex" (string @-> returning uint) in
  let idx = if_nametoindex ifname |> Unsigned.UInt.to_int in
  if idx = 0 then failwith ("Interface not found: " ^ ifname) else idx
;;

(* Internal: setup and attach BPF, returns cleanup function *)
let setup ~interface ~target_ips ?debounce_ms () =
  let ifindex = get_ifindex interface in
  let debounce_ns =
    match debounce_ms with
    | Some ms -> Unsigned.UInt64.of_int (ms * 1_000_000)
    | None -> Unsigned.UInt64.zero
  in
  (* Set up TC hook *)
  let tc_hook = make C.Types.Bpf_tc.hook in
  setf tc_hook C.Types.Bpf_tc.ifindex ifindex;
  setf tc_hook C.Types.Bpf_tc.attach_point `EGRESS;
  setf tc_hook C.Types.Bpf_tc.sz (Unsigned.Size_t.of_int (sizeof C.Types.Bpf_tc.hook));
  let tc_opts = make C.Types.Bpf_tc.Opts.t in
  setf tc_opts C.Types.Bpf_tc.Opts.handle (Unsigned.UInt32.of_int 1);
  setf tc_opts C.Types.Bpf_tc.Opts.priority (Unsigned.UInt32.of_int 1);
  setf
    tc_opts
    C.Types.Bpf_tc.Opts.sz
    (Unsigned.Size_t.of_int (sizeof C.Types.Bpf_tc.Opts.t));
  (* Try to clean up existing hook first to avoid conflicts *)
  ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook));
  (* Load BPF *)
  let obj = bpf_object_open (find_bpf_object ()) in
  let cleanup ~hook_created =
    ignore (C.Functions.bpf_tc_detach (addr tc_hook) (addr tc_opts));
    if hook_created then ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook));
    bpf_object_close obj
  in
  try
    bpf_object_load obj;
    (* Add target IPs to appropriate maps *)
    let map_v4 = bpf_object_find_map_by_name obj "target_ips_v4" in
    let map_v6 = bpf_object_find_map_by_name obj "target_ips_v6" in
    let dummy = Unsigned.UInt8.one in
    List.iter
      (fun ip ->
         match ip with
         | Ipaddr.V4 v4 ->
           let bytes = Ipaddr.V4.to_octets v4 in
           let int_val =
             let b i = Char.code bytes.[i] in
             Int32.(
               logor
                 (shift_left (of_int (b 3)) 24)
                 (logor
                    (shift_left (of_int (b 2)) 16)
                    (logor (shift_left (of_int (b 1)) 8) (of_int (b 0)))))
           in
           let uint32_val = Unsigned.UInt32.of_int32 int_val in
           bpf_map_update_elem ~key_ty:uint32_t ~val_ty:uint8_t map_v4 uint32_val dummy
         | Ipaddr.V6 v6 ->
           (* Convert 16 bytes string to CArray for BPF map *)
           let bytes = Ipaddr.V6.to_octets v6 in
           let key_arr = CArray.make uint8_t 16 in
           for i = 0 to 15 do
             CArray.set key_arr i (Unsigned.UInt8.of_int (Char.code bytes.[i]))
           done;
           bpf_map_update_elem
             ~key_ty:(array 16 uint8_t)
             ~val_ty:uint8_t
             map_v6
             key_arr
             dummy)
      target_ips;
    (* Configure debounce *)
    let debounce_map = bpf_object_find_map_by_name obj "debounce_config" in
    bpf_map_update_elem ~key_ty:int ~val_ty:uint64_t debounce_map 0 debounce_ns;
    (* Create and attach TC hook *)
    let hook_created = C.Functions.bpf_tc_hook_create (addr tc_hook) = 0 in
    let prog = bpf_object_find_program_by_name obj "packet_filter_egress" in
    setf tc_opts C.Types.Bpf_tc.Opts.prog_fd prog.fd;
    setf tc_opts C.Types.Bpf_tc.Opts.flags (Unsigned.UInt32.of_int 1);
    let err = C.Functions.bpf_tc_attach (addr tc_hook) (addr tc_opts) in
    if err <> 0
    then (
      cleanup ~hook_created;
      failwith (Printf.sprintf "Failed to attach TC filter: %d" err));
    let events_map = bpf_object_find_map_by_name obj "events" in
    events_map, fun () -> cleanup ~hook_created
  with
  | e ->
    bpf_object_close obj;
    raise e
;;

let start ~interface ~target_ips ?debounce_ms ~stop callback =
  let events_map, cleanup = setup ~interface ~target_ips ?debounce_ms () in
  let handle_event _ctx data _sz =
    let ev = !@(from_voidp packet_event data) in
    callback
      ~dst_ip:(ip_of_event ev)
      ~timestamp:(Unsigned.UInt64.to_int64 (getf ev ev_ts));
    0
  in
  RingBuffer.init events_map ~callback:handle_event (fun rb ->
    while not !stop do
      ignore
        (try RingBuffer.poll rb ~timeout:100 with
         | _ ->
           stop := true;
           -1)
    done);
  cleanup ()
;;

let start_eio ~sw ~interface ~target_ips ?debounce_ms callback =
  let events_map, cleanup = setup ~interface ~target_ips ?debounce_ms () in
  (* Register cleanup with switch *)
  Eio.Switch.on_release sw cleanup;
  let handle_event _ctx data _sz =
    let ev = !@(from_voidp packet_event data) in
    callback
      ~dst_ip:(ip_of_event ev)
      ~timestamp:(Unsigned.UInt64.to_int64 (getf ev ev_ts));
    0
  in
  (* Poll loop - check for cancellation between polls *)
  RingBuffer.init events_map ~callback:handle_event (fun rb ->
    try
      while true do
        Eio.Fiber.check ();
        (* Check if switch was cancelled *)
        ignore (RingBuffer.poll rb ~timeout:100)
      done
    with
    | Eio.Cancel.Cancelled _ -> ())
;;
