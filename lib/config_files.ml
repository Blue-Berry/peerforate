open Core

let config_dir () =
  let home = Sys.getenv_exn "HOME" in
  let config_dir = Filename.concat home ".config" in
  Filename.concat config_dir "peerforate"
;;

let rec ensure_directory path =
  if String.equal path Filename.dir_sep
  then ()
  else (
    let parent = Filename.dirname path in
    if not (String.equal parent path) then ensure_directory parent;
    match Core_unix.mkdir path ~perm:0o700 with
    | () -> ()
    | exception exn ->
      (match Core_unix.stat path with
       | { st_kind = S_DIR; _ } -> ()
       | _ -> raise exn))
;;

let ensure_config_dir () = config_dir () |> ensure_directory

let read_config_file ~filename =
  let path = Filename.concat (config_dir ()) filename in
  match Stdlib.Sys.file_exists path with
  | false -> ""
  | true -> In_channel.read_all path |> String.strip
;;

let write_config_file ~filename contents =
  ensure_config_dir ();
  let path = Filename.concat (config_dir ()) filename in
  Out_channel.with_file path ~perm:0o600 ~f:(fun oc ->
    Out_channel.output_string oc contents)
;;
