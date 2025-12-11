(* Packet Filter - Detect packets to a specific IP with debouncing
 *
 * Usage: sudo ./packet_filter.exe <interface> <target_ip> [debounce_ms]
 * Example: sudo ./packet_filter.exe wg0 10.0.0.1 1000
 *)

open Ctypes
open Libbpf
open Libbpf_maps

(* Find BPF object file *)
let obj_path =
  let candidates =
    [ Filename.concat (Filename.dirname Sys.executable_name) "packet_filter.bpf.o"
    ; "packet_filter.bpf.o"
    ; "client/ebpf/packet_filter.bpf.o"
    ]
  in
  match List.find_opt Sys.file_exists candidates with
  | Some path -> path
  | None -> failwith "Cannot find packet_filter.bpf.o"
;;

(* Event structure matching packet_filter.h *)
let packet_event : [ `Packet_event ] structure typ = structure "packet_event"
let dst_ip = field packet_event "dst_ip" uint32_t
let ts = field packet_event "ts" uint64_t
let () = seal packet_event

(* IP string to network byte order *)
let parse_ip ip_str =
  match String.split_on_char '.' ip_str |> List.map int_of_string with
  | [ a; b; c; d ] ->
    Unsigned.UInt64.of_int (a lor (b lsl 8) lor (c lsl 16) lor (d lsl 24))
  | _ -> failwith "Invalid IP"
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

(* ========== YOUR CALLBACK HERE ========== *)
let on_packet_detected ~dst_ip ~timestamp =
  Printf.printf "[%Ld] Packet to %s detected\n%!" timestamp dst_ip
;;

(* Ring buffer handler *)
let handle_event _ctx data _sz =
  let ev = !@(from_voidp packet_event data) in
  on_packet_detected
    ~dst_ip:(ip_to_string (getf ev dst_ip))
    ~timestamp:(Unsigned.UInt64.to_int64 (getf ev ts));
  0
;;

let () =
  if Array.length Sys.argv < 3
  then (
    Printf.eprintf "Usage: %s <interface> <target_ip> [debounce_ms]\n" Sys.argv.(0);
    Printf.eprintf "Example: %s wg0 10.0.0.1 1000\n" Sys.argv.(0);
    exit 1);
  let ifname = Sys.argv.(1) in
  let target_ip = parse_ip Sys.argv.(2) in
  let debounce_ns =
    if Array.length Sys.argv > 3
    then Unsigned.UInt64.of_int (int_of_string Sys.argv.(3) * 1_000_000)
    else Unsigned.UInt64.zero
  in
  let ifindex = get_ifindex ifname in
  Printf.printf
    "Monitoring packets to %s on %s (debounce: %s ms)\n%!"
    Sys.argv.(2)
    ifname
    (if Array.length Sys.argv > 3 then Sys.argv.(3) else "0");
  (* Signal handling *)
  let running = ref true in
  Sys.(set_signal sigint (Signal_handle (fun _ -> running := false)));
  Sys.(set_signal sigterm (Signal_handle (fun _ -> running := false)));
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
  let obj = bpf_object_open obj_path in
  bpf_object_load obj;
  (* Configure target IP and debounce *)
  let config_map = bpf_object_find_map_by_name obj "filter_config" in
  bpf_map_update_elem ~key_ty:int ~val_ty:uint64_t config_map 0 target_ip;
  bpf_map_update_elem ~key_ty:int ~val_ty:uint64_t config_map 1 debounce_ns;
  (* Attach TC *)
  let hook_created = C.Functions.bpf_tc_hook_create (addr tc_hook) = 0 in
  let prog = bpf_object_find_program_by_name obj "packet_filter_egress" in
  setf tc_opts C.Types.Bpf_tc.Opts.prog_fd prog.fd;
  setf tc_opts C.Types.Bpf_tc.Opts.flags (Unsigned.UInt32.of_int 1);
  (* REPLACE *)
  if C.Functions.bpf_tc_attach (addr tc_hook) (addr tc_opts) <> 0
  then (
    if hook_created then ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook));
    bpf_object_close obj;
    failwith "Failed to attach TC");
  Printf.printf "Filter attached. Press Ctrl-C to stop.\n%!";
  (* Poll for events *)
  let events_map = bpf_object_find_map_by_name obj "events" in
  RingBuffer.init events_map ~callback:handle_event (fun rb ->
    while !running do
      ignore
        (try RingBuffer.poll rb ~timeout:100 with
         | _ ->
           running := false;
           -1)
    done);
  (* Cleanup *)
  ignore (C.Functions.bpf_tc_detach (addr tc_hook) (addr tc_opts));
  if hook_created then ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook));
  bpf_object_close obj;
  Printf.printf "Done.\n%!"
;;
