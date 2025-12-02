type t =
  { listen_port : int
  ; max_message_age_s : float
  ; key : Wg_nat.Crypto.X25519.secret
  }

val sexp_of_t : t -> Core.Sexp.t
val t_of_sexp : Core.Sexp.t -> t
val to_string : t -> string
val of_string : string -> t
val filename : string
val read_server_config : unit -> t option
val write_server_config : t -> unit
val init_server_config : unit -> t
