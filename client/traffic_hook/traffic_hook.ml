(* Traffic Hook - eBPF-based egress packet monitoring *)

open Ctypes
open Libbpf
open Libbpf_maps

type callback = dst_ip:string -> timestamp:int64 -> unit

let packet_event : [ `Packet_event ] structure typ = structure "packet_event"
let ev_dst_ip = field packet_event "dst_ip" uint32_t
let ev_ts = field packet_event "ts" uint64_t
let () = seal packet_event

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

let parse_ip_to_uint32 ip_str =
  match String.split_on_char '.' ip_str |> List.map int_of_string with
  | [ a; b; c; d ] ->
    Unsigned.UInt32.of_int (a lor (b lsl 8) lor (c lsl 16) lor (d lsl 24))
  | _ -> failwith ("Invalid IP address: " ^ ip_str)
;;

let ip_to_string ip =
  let ip = Unsigned.UInt32.to_int32 ip in
  Printf.sprintf
    "%ld.%ld.%ld.%ld"
    Int32.(logand ip 0xFFl)
    Int32.(logand (shift_right_logical ip 8) 0xFFl)
    Int32.(logand (shift_right_logical ip 16) 0xFFl)
    Int32.(logand (shift_right_logical ip 24) 0xFFl)
;;

(* Get interface index *)
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
  (* Load BPF *)
  let obj = bpf_object_open (find_bpf_object ()) in
  let cleanup ~hook_created =
    ignore (C.Functions.bpf_tc_detach (addr tc_hook) (addr tc_opts));
    if hook_created then ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook));
    bpf_object_close obj
  in
  try
    bpf_object_load obj;
    (* Add all target IPs to the hash map *)
    let ips_map = bpf_object_find_map_by_name obj "target_ips" in
    let dummy = Unsigned.UInt8.one in
    List.iter
      (fun ip_str ->
         let ip = parse_ip_to_uint32 ip_str in
         bpf_map_update_elem ~key_ty:uint32_t ~val_ty:uint8_t ips_map ip dummy)
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
      ~dst_ip:(ip_to_string (getf ev ev_dst_ip))
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
      ~dst_ip:(ip_to_string (getf ev ev_dst_ip))
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
