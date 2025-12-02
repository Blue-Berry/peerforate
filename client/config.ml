open! Core

type t =
  { server_endpoint : string
  ; server_port : int
  ; wg_interface : string
  ; wg_port : int
  ; server_dns_port : int
  }
[@@deriving sexp]

let to_string t = sexp_of_t t |> Sexp.to_string_hum
let of_string s = Sexp.of_string s |> t_of_sexp
let filename = "client_config"

let read_config () =
  Wg_nat.Config.read_config_file ~filename
  |> function
  | "" -> None
  | s -> Some (of_string s)
;;

let write_config t = Wg_nat.Config.write_config_file ~filename (to_string t)

let init_config ~server_endpoint ~server_port ~wg_interface =
  let config =
    { server_endpoint
    ; server_port
    ; wg_interface
    ; wg_port = 51820
    ; server_dns_port = 5354
    }
  in
  write_config config;
  config
;;
