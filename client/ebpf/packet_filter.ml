(* Packet Filter Example using ocaml-libbpf
 *
 * This example demonstrates how to:
 * 1. Load an eBPF program that monitors network traffic
 * 2. Set a target IP address to filter packets for
 * 3. Receive events in OCaml when packets to/from that IP are detected
 *
 * Usage: sudo ./packet_filter.exe <interface> <target_ip>
 * Example: sudo ./packet_filter.exe eth0 10.0.0.1
 *)

open Ctypes
open Libbpf
open Libbpf_maps

(* Find the BPF object file - check multiple locations *)
let obj_path =
  let exe_dir = Filename.dirname Sys.executable_name in
  let candidates =
    [ Filename.concat exe_dir "packet_filter.bpf.o"
    ; (* Next to executable *)
      "packet_filter.bpf.o"
    ; (* Current directory *)
      "client/ebpf/packet_filter.bpf.o" (* From project root *)
    ]
  in
  match List.find_opt Sys.file_exists candidates with
  | Some path -> path
  | None ->
    Printf.eprintf "Error: Cannot find packet_filter.bpf.o\n";
    Printf.eprintf "Searched in:\n";
    List.iter (fun p -> Printf.eprintf "  - %s\n" p) candidates;
    Printf.eprintf
      "\n\
       Try running from the project root or copy packet_filter.bpf.o next to the \
       executable.\n";
    exit 1
;;

let egress_prog_name = "packet_filter_egress"
let target_ip_map_name = "target_ip"
let events_map_name = "events"

(* packet_event structure layout matching packet_filter.h *)
let packet_event : [ `Packet_event ] structure typ = Ctypes.structure "packet_event"
let ( -: ) ty label = field packet_event label ty
let src_ip = uint32_t -: "src_ip"
let dst_ip = uint32_t -: "dst_ip"
let src_port = uint16_t -: "src_port"
let dst_port = uint16_t -: "dst_port"
let protocol = uint8_t -: "protocol"
let pkt_len = uint16_t -: "pkt_len"
let _padding = uint8_t -: "_padding" (* alignment padding *)
let ts = uint64_t -: "ts"
let () = seal packet_event

(* Convert IP address from network byte order to string *)
let ip_to_string ip =
  let ip = Unsigned.UInt32.to_int32 ip in
  let b1 = Int32.(to_int (logand ip 0xFFl)) in
  let b2 = Int32.(to_int (logand (shift_right_logical ip 8) 0xFFl)) in
  let b3 = Int32.(to_int (logand (shift_right_logical ip 16) 0xFFl)) in
  let b4 = Int32.(to_int (logand (shift_right_logical ip 24) 0xFFl)) in
  Printf.sprintf "%d.%d.%d.%d" b1 b2 b3 b4
;;

(* Convert port from network byte order *)
let port_to_int port =
  let p = Unsigned.UInt16.to_int port in
  ((p land 0xFF) lsl 8) lor ((p lsr 8) land 0xFF)
;;

(* Protocol number to name *)
let protocol_name proto =
  match Unsigned.UInt8.to_int proto with
  | 1 -> "ICMP"
  | 6 -> "TCP"
  | 17 -> "UDP"
  | n -> Printf.sprintf "proto(%d)" n
;;

(* Direction to string *)

(* Parse IP address string to network byte order uint32 *)
let parse_ip ip_str =
  let parts = String.split_on_char '.' ip_str in
  match List.map int_of_string parts with
  | [ b1; b2; b3; b4 ] ->
    let ip = b1 lor (b2 lsl 8) lor (b3 lsl 16) lor (b4 lsl 24) in
    Unsigned.UInt32.of_int ip
  | _ -> failwith "Invalid IP address format"
;;

(* Get interface index by name *)
let get_ifindex ifname =
  let fd = Unix.(socket PF_INET SOCK_DGRAM 0) in
  (* Use if_nametoindex via FFI *)
  let if_nametoindex = Foreign.foreign "if_nametoindex" (string @-> returning uint) in
  let idx = if_nametoindex ifname in
  Unix.close fd;
  if Unsigned.UInt.to_int idx = 0
  then failwith (Printf.sprintf "Interface %s not found" ifname)
  else Unsigned.UInt.to_int idx
;;

(* ============================================================
 * YOUR CUSTOM CALLBACK - This is where you put your OCaml code
 * that runs when a packet to the target IP is detected!
 * ============================================================ *)
let on_packet_detected event =
  let src = ip_to_string (getf event src_ip) in
  let dst = ip_to_string (getf event dst_ip) in
  let sport = port_to_int (getf event src_port) in
  let dport = port_to_int (getf event dst_port) in
  let proto = protocol_name (getf event protocol) in
  let dir = "EGRESS" in
  let len = Unsigned.UInt16.to_int (getf event pkt_len) in
  let timestamp = Unsigned.UInt64.to_int64 (getf event ts) in
  (* ============================================
   * PUT YOUR CUSTOM OCAML CODE HERE!
   * This runs every time a matching packet is detected.
   * 
   * Examples of what you could do:
   * - Log to a file
   * - Update application state
   * - Trigger network operations
   * - Send notifications
   * - Collect statistics
   * ============================================ *)
  Printf.printf
    "[%Ld] %s %s:%d -> %s:%d (%s, %d bytes)\n%!"
    timestamp
    dir
    src
    sport
    dst
    dport
    proto
    len;
  (* Example: you could call other functions here *)
  (* my_custom_handler ~src ~dst ~proto ~len; *)
  ()
;;

(* Ring buffer callback wrapper *)
let handle_event _ctx data _sz =
  let ev = !@(from_voidp packet_event data) in
  on_packet_detected ev;
  0
;;

let () =
  (* Parse command line arguments *)
  if Array.length Sys.argv < 3
  then (
    Printf.eprintf "Usage: %s <interface> <target_ip>\n" Sys.argv.(0);
    Printf.eprintf "Example: %s eth0 10.0.0.1\n" Sys.argv.(0);
    exit 1);
  let ifname = Sys.argv.(1) in
  let target_ip_str = Sys.argv.(2) in
  let target_ip_val = parse_ip target_ip_str in
  let ifindex = get_ifindex ifname in
  Printf.printf
    "Monitoring packets to/from %s on interface %s (ifindex %d)\n%!"
    target_ip_str
    ifname
    ifindex;
  (* Set up signal handlers for clean shutdown *)
  let running = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> running := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);
  (* Track whether we created the TC hooks *)
  let egress_hook_created = ref false in
  (* Set up TC hook for egress (outgoing packets) *)
  let tc_hook_egress = make C.Types.Bpf_tc.hook in
  setf tc_hook_egress C.Types.Bpf_tc.ifindex ifindex;
  setf tc_hook_egress C.Types.Bpf_tc.attach_point `EGRESS;
  let sz = Ctypes.sizeof C.Types.Bpf_tc.hook in
  setf tc_hook_egress C.Types.Bpf_tc.sz (Unsigned.Size_t.of_int sz);
  let tc_opts_egress = make C.Types.Bpf_tc.Opts.t in
  setf tc_opts_egress C.Types.Bpf_tc.Opts.handle (Unsigned.UInt32.of_int 1);
  setf tc_opts_egress C.Types.Bpf_tc.Opts.priority (Unsigned.UInt32.of_int 1);
  let sz = Ctypes.sizeof C.Types.Bpf_tc.Opts.t in
  setf tc_opts_egress C.Types.Bpf_tc.Opts.sz (Unsigned.Size_t.of_int sz);
  (* Open and load BPF object *)
  let obj = bpf_object_open obj_path in
  (* Set the target IP in the BPF map before loading *)
  let before_load obj =
    (* Find the target_ip map and set our filter IP *)
    let map = bpf_object_find_map_by_name obj target_ip_map_name in
    bpf_map_update_elem ~key_ty:int ~val_ty:uint32_t map 0 target_ip_val
  in
  (* We need to manually handle the lifecycle since TC requires special attachment *)
  bpf_object_load obj;
  (* Set target IP after load *)
  before_load obj;
  let egress_prog = bpf_object_find_program_by_name obj egress_prog_name in
  (* Create and attach egress hook *)
  let err = C.Functions.bpf_tc_hook_create (addr tc_hook_egress) in
  if err = 0 then egress_hook_created := true;
  if err <> 0 && err <> -17 (* EEXIST *)
  then (
    Printf.eprintf "Failed to create egress TC hook: %d\n" err;
    bpf_object_close obj;
    exit 1);
  setf tc_opts_egress C.Types.Bpf_tc.Opts.prog_fd egress_prog.fd;
  (* Set BPF_TC_F_REPLACE flag (value 1) to replace any existing filter *)
  setf tc_opts_egress C.Types.Bpf_tc.Opts.flags (Unsigned.UInt32.of_int 1);
  let err = C.Functions.bpf_tc_attach (addr tc_hook_egress) (addr tc_opts_egress) in
  if err <> 0
  then (
    Printf.eprintf "Failed to attach egress TC program: %d\n" err;
    if !egress_hook_created
    then ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook_egress));
    bpf_object_close obj;
    exit 1);
  Printf.printf "Egress filter attached\n%!";
  (* Set up ring buffer for receiving events *)
  let events_map = bpf_object_find_map_by_name obj events_map_name in
  Printf.printf "\nListening for packets to/from %s...\n%!" target_ip_str;
  Printf.printf "Press Ctrl-C to stop.\n\n%!";
  Printf.printf
    "%-20s %-8s %-21s %-21s %-6s %s\n%!"
    "TIMESTAMP"
    "DIR"
    "SOURCE"
    "DEST"
    "PROTO"
    "LENGTH";
  Printf.printf "%s\n%!" (String.make 80 '-');
  (* Initialize ring buffer and poll for events *)
  RingBuffer.init events_map ~callback:handle_event (fun rb ->
    while !running do
      (* Poll with 100ms timeout *)
      let _ =
        try RingBuffer.poll rb ~timeout:100 with
        | _ ->
          running := false;
          -1
      in
      ()
    done);
  (* Cleanup *)
  Printf.printf "\nShutting down...\n%!";
  ignore (C.Functions.bpf_tc_detach (addr tc_hook_egress) (addr tc_opts_egress));
  if !egress_hook_created
  then ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook_egress));
  bpf_object_close obj;
  Printf.printf "Done.\n%!"
;;
