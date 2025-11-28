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
type auth_status =
  | Allow
  | Deny
  | New

let authenticate (t : t) { endpoint; key } : auth_status =
  match
    List.find t ~f:(fun { server; _ } -> Endpoint.equal server.endpoint endpoint)
    |> Option.bind ~f:(fun k -> Some String.(k.server.key = key))
  with
  | None -> New
  | Some false -> Deny
  | Some true -> Allow
;;
