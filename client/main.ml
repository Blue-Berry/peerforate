open! Core
module P = Wg_nat.Request.Packet
module R = Wg_nat.Reply.Packet
module K = Wglib.Wgapi.Key

(* TODO: *)
(* Create a peer config system  *)

let get_config () =
  Config.read_config ()
  |> function
  | Some c -> c
  | None ->
    Config.init_config ~server_endpoint:"127.0.0.1" ~server_port:49918 ~wg_interface:"wg8"
;;

let get_key ~net ~clock (conf : Config.t) =
  let open Dnslib in
  Eio.Switch.run
  @@ fun sw ->
  let nameservers =
    `Udp, [ Ipaddr.of_string_exn conf.server_endpoint, conf.server_dns_port ]
  in
  let client = Client.create ~nameservers ~timeout:5_000_000_000L ~sw ~net ~clock () in
  match Client.get_resource_record client Dns.Rr_map.Txt (Utils.name "key.vpn.local") with
  | Ok (_ttl, txt_set) ->
    let record = Dns.Rr_map.Txt_set.elements txt_set |> List.hd in
    record
  | _ -> None
;;

let main server_key ~sw ~clock (conf : Config.t) : unit =
  let wg_intrf = Wgctrl.get_wg_intrf conf in
  Traffic_mon.start ~sw ~clock ~wg_intrf ~conf ~server_key
;;

let tofu = Tofu.read_known_servers ()

let () =
  Logs.set_level (Some Logs.Info);
  Logs.set_reporter (Logs.format_reporter ());
  Eio_main.run
  @@ fun env ->
  (* Initialize random number generator *)
  Mirage_crypto_rng_unix.use_default ();
  let conf = get_config () in
  let net : Eio_unix.Net.t = (Eio.Stdenv.net env :> Eio_unix.Net.t) in
  let clock = Eio.Stdenv.clock env in
  let key = get_key ~net ~clock conf |> Option.value_exn ~message:"Dns not reachable" in
  let tofu, authed = Tofu.authenticate tofu Tofu.{ key; endpoint = "127.0.0.1", 5354 } in
  Tofu.write_known_servers tofu;
  match authed with
  | false -> Logs.err @@ fun m -> m "Server not authenticated"
  | true -> Eio.Switch.run ~name:"Main" (fun sw -> main key conf ~clock ~sw)
;;
