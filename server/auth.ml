open Core
module P = Wg_nat.Request.Packet
module K = Wglib.Wgapi.Key

let is_valid_mac packet (conf : Config.t) =
  let client_mac = P.copy_t_mac packet in
  let hst_key = P.copy_t_hst_key packet |> K.of_string in
  let dest_key = P.copy_t_dest_key packet |> K.of_string in
  let timestamp = P.get_t_timestamp packet in
  let priv_key = conf.key in
  let gen_mac =
    P.gen_mac
      ~pub_key:(hst_key |> K.to_string)
      ~priv_key
      ~hst_key:(K.to_string hst_key)
      ~dest_key:(K.to_string dest_key)
      timestamp
  in
  String.(client_mac = gen_mac)
;;

let is_valid_timestamp packet (conf : Config.t) =
  let timestamp = P.get_t_timestamp packet in
  let now = Ptime.v (Ptime_clock.now_d_ps ()) |> Ptime.to_span |> Ptime.Span.to_float_s in
  let timestamp = Int64.to_float timestamp in
  let age = now -. timestamp in
  Float.(age < conf.max_message_age_s) && Float.(age >= 0.)
;;
