type t =
  { server_endpoint : string
  ; server_port : int
  ; wg_interface : string
  ; wg_port : int
  ; server_dns_port : int
  }

val read_config : unit -> t option
val write_config : t -> unit
val init_config : server_endpoint:string -> server_port:int -> wg_interface:string -> t
