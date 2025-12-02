open Core

module Endpoint = struct
  type t = string * int [@@deriving sexp]

  let equal ((a_addr, a_port) : t) ((b_addr, b_port) : t) : bool =
    String.(a_addr = b_addr) && Int.(a_port = b_port)
  ;;
end

type server =
  { endpoint : Endpoint.t
  ; key : string
  }
[@@deriving sexp]

type entry =
  { server : server
  ; first_seen : int64
  }
[@@deriving sexp]

type t = entry list [@@deriving sexp]

let to_string t = sexp_of_t t |> Sexp.to_string_mach
let of_string s = Sexp.of_string s |> t_of_sexp
let filename = "known_servers"

let read_known_servers () =
  Wg_nat.Config.read_config_file ~filename
  |> function
  | "" -> []
  | s -> of_string s
;;

let write_known_servers t = Wg_nat.Config.write_config_file ~filename (to_string t)

(*
                                                                               
                    yes    ┌─────────────────┐   no                           
                  ┌────────┼ Endpoint known? ┼─────────────────┐              
                  │        └─────────────────┘                 │              
                  │                                            │              
                  │                                            │              
          ┌───────▼────────┐                          ┌────────▼─────────┐    
   ┌──────┼ matching key?  │                          │ new server usage │    
   │      └───────────────┬┘                          └──────────────────┘    
   │                      │                                                   
   │                      │                                                   
   │yes                   │no                                                 
   │                      │                                                   
   │                      │                                                   
┌──▼────┐             ┌───▼──┐                                                
│ allow │             │ deny │                                                
└───────┘             └──────┘                                                
 *)

let authenticate (t : t) ({ endpoint; key } as new_server) =
  match
    List.find t ~f:(fun { server; _ } -> Endpoint.equal server.endpoint endpoint)
    |> Option.bind ~f:(fun k -> Some String.(k.server.key = key))
  with
  | Some false -> t, false
  | Some true -> t, true
  | None ->
    let first_seen = Ptime_clock.now () |> Ptime.to_float_s |> Float.to_int64 in
    { server = new_server; first_seen } :: t, true
;;
