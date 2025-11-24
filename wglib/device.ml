module type Device = sig
  module DeviceError = Wgapi.Interface.DeviceError

  val add_peers : Wgapi.Peer.t list -> (unit, DeviceError.t) result
  val set_peers : Wgapi.Peer.t list -> (unit, DeviceError.t) result
  val get_peers : unit -> (Wgapi.Peer.t list, string) result
  val configure_peers : 'a -> 'b
  val remove_peers : Wgapi.Peer.t list -> (unit, DeviceError.t) result
end

let new_device ~name ~listen_port ~private_key () =
  let device = Wgapi.Interface.create ~name ~listen_port ~private_key ~peers:[] () in
  match Wgapi.Interface.set_device device with
  | Error e -> Error e
  | Ok () ->
    Ok
      (let module NewDevice : Device = struct
         module DeviceError = Wgapi.Interface.DeviceError

         let add_peers = Wgapi.Interface.add_peers device
         let set_peers = Wgapi.Interface.set_peers device
         let configure_peers = Wgapi.Interface.configure_peers
         let remove_peers = Wgapi.Interface.remove_peers device

         let get_peers () =
           Wgapi.Interface.get_device name
           |> Result.map (fun device -> Wgapi.Interface.(device.peers))
         ;;
       end
       in
      let dev = (module NewDevice : Device) in
      dev)
;;
