open! Core

type t =
  { listen_port : int
  ; max_message_age_s : float
  ; key : Wg_nat.Crypto.X25519.secret
  }

let sexp_of_t t =
  Sexp.(
    List
      [ List [ Atom "listen_port"; Int.sexp_of_t t.listen_port ]
      ; List [ Atom "max_message_age_s"; Float.sexp_of_t t.max_message_age_s ]
      ; List
          [ Atom "key"
          ; Atom (Wg_nat.Crypto.X25519.secret_to_octets t.key |> Base64.encode_string)
          ]
      ])
;;

let t_of_sexp s =
  match s with
  | Sexp.List
      [ Sexp.List [ Sexp.Atom "listen_port"; listen_port_sexp ]
      ; Sexp.List [ Sexp.Atom "max_message_age_s"; max_message_age_sexp ]
      ; Sexp.List [ Sexp.Atom "key"; Sexp.Atom key_base64 ]
      ] ->
    let listen_port = Int.t_of_sexp listen_port_sexp in
    let max_message_age_s = Float.t_of_sexp max_message_age_sexp in
    let key_octets = Base64.decode_exn key_base64 in
    let key, _ =
      Wg_nat.Crypto.X25519.secret_of_octets key_octets
      |> function
      | Ok key -> key
      | Error _ -> failwith "Invalid key"
    in
    { listen_port; max_message_age_s; key }
  | _ -> failwith "Invalid sexp format for server config"
;;

let to_string t = sexp_of_t t |> Sexp.to_string_hum
let of_string s = Sexp.of_string s |> t_of_sexp
let filename = "server_config"

let read_server_config () =
  Wg_nat.Config.read_config_file ~filename
  |> function
  | "" -> None
  | s -> Some (of_string s)
;;

let write_server_config t = Wg_nat.Config.write_config_file ~filename (to_string t)

let init_server_config () =
  let config =
    { listen_port = 49918
    ; max_message_age_s = 2.0
    ; key = Wg_nat.Crypto.X25519.gen_key () |> fst
    }
  in
  write_server_config config;
  config
;;
