val start
  :  sw:Eio.Switch.t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Resource.t
  -> wg_intrf:Wglib.Wgapi.Interface.t
  -> conf:Config.t
  -> server_key:string
  -> unit
