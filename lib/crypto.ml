module X25519 = Mirage_crypto_ec.X25519
open Core

let () = Mirage_crypto_rng_unix.use_default ()

let rng_priv_key, rng_pub_key =
  X25519.secret_of_octets "11111111111111111111111111111111"
  |> Result.ok
  |> Option.value_exn
;;

let int_to_hex i = Printf.sprintf "%02x" i

let string_to_hex s =
  String.to_sequence s
  |> Sequence.map ~f:(fun c -> Char.to_int c |> int_to_hex)
  |> Sequence.to_list
  |> String.concat
;;

let gen_mac ~priv_key ~pub_key ~message =
  Printf.sprintf
    "Generating MAC with priv_key %s\n and pub_key %s\n"
    (string_to_hex (X25519.secret_to_octets priv_key))
    (string_to_hex pub_key)
  |> print_endline;
  match X25519.key_exchange priv_key pub_key with
  | Error _ -> None
  | Ok key ->
    Printf.sprintf "Generating MAC with secret: %s\n" (string_to_hex key) |> print_endline;
    Some (Mirage_crypto.Poly1305.mac ~key message)
;;
