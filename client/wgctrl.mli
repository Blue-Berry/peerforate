val get_wg_intrf : Config.t -> Wglib.Wgapi.Interface.t

val update_peer
  :  Wglib.Wgapi.Interface.t
  -> Wglib.Wgapi.Key.t
  -> Ipaddr.t
  -> int
  -> (unit, Wglib.Wgapi.Interface.DeviceError.t) result
