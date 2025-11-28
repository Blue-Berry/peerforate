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

let known_servers_dir () =
  let home = Sys.getenv_exn "HOME" in
  let config_dir = Filename.concat home ".config" in
  Filename.concat config_dir "peerforate"
;;

let known_servers_path () = Filename.concat (known_servers_dir ()) "known_servers"

let rec ensure_directory path =
  if String.equal path Filename.dir_sep
  then ()
  else (
    let parent = Filename.dirname path in
    if not (String.equal parent path) then ensure_directory parent;
    match Core_unix.mkdir path ~perm:0o700 with
    | () -> ()
    | exception exn ->
      (match Core_unix.stat path with
       | { st_kind = S_DIR; _ } -> ()
       | _ -> raise exn))
;;

let ensure_known_servers_dir () = known_servers_dir () |> ensure_directory

let read_known_servers () =
  let path = known_servers_path () in
  if Stdlib.Sys.file_exists path then
    let contents = In_channel.read_all path in
    if String.(is_empty (strip contents)) then [] else of_string contents
  else []
;;

let write_known_servers t =
  ensure_known_servers_dir ();
  let path = known_servers_path () in
  Out_channel.with_file path ~perm:0o600 ~f:(fun oc ->
    Out_channel.output_string oc (to_string t))
;;

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
