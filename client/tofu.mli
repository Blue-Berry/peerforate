module Endpoint : sig
  type t = string * int

  val t_of_sexp : Sexplib0.Sexp.t -> t
  val sexp_of_t : t -> Sexplib0.Sexp.t
  val equal : t -> t -> bool
end

type server =
  { endpoint : Endpoint.t
  ; key : string
  }

type entry =
  { server : server
  ; first_seen : int64
  }

type t = entry list

val read_known_servers : unit -> t
val write_known_servers : t -> unit

type auth_status =
  | Allow
  | Deny

val authenticate : t -> server -> t * auth_status
