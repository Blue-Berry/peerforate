module type Device = sig
  module DeviceError = Wgapi.Interface.DeviceError

  val add_peers : Wgapi.Peer.t list -> (unit, DeviceError.t) result
  val set_peers : Wgapi.Peer.t list -> (unit, DeviceError.t) result
  val get_peers : unit -> (Wgapi.Peer.t list, string) result
  val configure_peers : 'a -> 'b
  val remove_peers : Wgapi.Peer.t list -> (unit, DeviceError.t) result
end

val new_device
  :  name:string
  -> listen_port:int
  -> private_key:Wgapi.Key.t
  -> unit
  -> ((module Device), Wgapi.Interface.DeviceError.t) result
