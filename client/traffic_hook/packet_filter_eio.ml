(* Example using Traffic_hook library with Eio *)

let () =
  if Array.length Sys.argv < 3
  then (
    Printf.eprintf "Usage: %s <interface> <ip1,ip2,...> [debounce_ms]\n" Sys.argv.(0);
    Printf.eprintf "Example: %s wg0 10.0.0.1,10.0.0.2 1000\n" Sys.argv.(0);
    exit 1);
  let interface = Sys.argv.(1) in
  let target_ips_str = String.split_on_char ',' Sys.argv.(2) in
  let target_subnets =
    List.map
      (fun s ->
         match Ipaddr.Prefix.of_string s with
         | Ok p -> p
         | Error (`Msg m) ->
           (match Ipaddr.of_string s with
            | Ok ip -> Ipaddr.Prefix.of_addr ip
            | Error _ -> failwith ("Invalid CIDR or IP: " ^ s ^ " (" ^ m ^ ")")))
      target_ips_str
  in
  let debounce_ms =
    if Array.length Sys.argv > 3 then Some (int_of_string Sys.argv.(3)) else None
  in
  Printf.printf
    "Monitoring packets to [%s] on %s (debounce: %s ms)\n%!"
    (String.concat ", " target_ips_str)
    interface
    (match debounce_ms with
     | Some ms -> string_of_int ms
     | None -> "0");
  let on_packet ~dst_ip ~timestamp =
    Eio.traceln "[%Ld] Packet to %s detected" timestamp (Ipaddr.to_string dst_ip)
  in
  Printf.printf "Press Ctrl-C to stop.\n%!";
  Eio_main.run
  @@ fun _env ->
  Eio.Switch.run
  @@ fun sw ->
  Traffic_hook.start_eio ~sw ~interface ~target_subnets ?debounce_ms on_packet;
  Printf.printf "Done.\n%!"
;;
