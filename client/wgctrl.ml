let get_wg_intrf (conf : Config.t) =
  let open Wglib.Wgapi in
  match Interface.get_device conf.wg_interface with
  | Ok d ->
    Logs.info (fun m ->
      m
        "Found wg interface: %s; Pub key: %s\n"
        d.name
        (d.public_key
         |> function
         | None -> ""
         | Some k -> Key.to_base64_string k));
    d
  | Error _ ->
    let private_key = Key.generate_private_key () in
    let public_key = Key.generate_public_key private_key in
    let interface =
      Interface.create
        ~private_key
        ~public_key
        ~listen_port:51820
        ~name:conf.wg_interface
        ()
    in
    Logs.info (fun m ->
      m
        "Created wg interface: %s; Pub key: %s\n"
        interface.name
        (interface.public_key
         |> function
         | None -> ""
         | Some k -> Key.to_base64_string k));
    (Interface.set_device interface
     |> function
     | Ok () -> ()
     | Error err ->
       Logs.err
       @@ fun m ->
       m "Failed to set wg interface: %s\n" (Interface.DeviceError.to_string err));
    interface
;;

let update_peer wg_intrf public_key (endpoint : Ipaddr.t) port =
  let open Wglib.Wgapi in
  let endpoint =
    match endpoint with
    | Ipaddr.V4 ip ->
      let endpoint : Endpoint.t = { addr = `V4 ip; port } in
      endpoint
    | Ipaddr.V6 ip ->
      let endpoint : Endpoint.t = { addr = `V6 ip; port } in
      endpoint
  in
  let peer = Peer.create ~endpoint ~persistent_keepalive_interval:25 ~public_key () in
  Interface.set_peers wg_intrf [ peer ]
;;
