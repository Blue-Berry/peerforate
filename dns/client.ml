(* DNS Client Library using Dns_client *)

(* TODO: change to functor? https://mirage.github.io/ocaml-dns/dns-client/Dns_client/module-type-S/index.html *)
let name s = Domain_name.(host_exn (of_string_exn s))

(* Query for TXT records using Dns_client.Pure *)
let query_txt ~sw ~net ~dst ~clock domain_name =
  let open Dns in
  let domain = name domain_name in
  (* Use Dns_client.Pure.make_query to create a DNS query *)
  let rng = Mirage_crypto_rng.generate ?g:None in
  let query_str, _query_state =
    Dns_client.Pure.make_query rng `Udp `None domain Rr_map.Txt
  in
  (* Send query and receive response *)
  let query_buf = Cstruct.of_string query_str in
  match Utils.query ~sw ~net ~dst ~query_buf ~clock with
  | None -> Error `Query_failed
  | Some resp_buf ->
    (* Decode response *)
    (match Packet.decode (Cstruct.to_string resp_buf) with
     | Error e -> Error (`Decode_error e)
     | Ok response ->
       (* Extract TXT records from answer *)
       (match response.Packet.data with
        | `Answer (answer, _) ->
          let raw_domain = Domain_name.raw domain in
          (match Domain_name.Map.find_opt raw_domain answer with
           | Some rr_map ->
             (* Extract TXT records from the Rr_map *)
             (match Dns.Rr_map.find Rr_map.Txt rr_map with
              | Some (ttl, txt_set) ->
                let txt_records = Rr_map.Txt_set.elements txt_set in
                Ok (ttl, txt_records)
              | None -> Error `Wrong_record_type)
           | None -> Error `No_answer)
        | _ -> Error `Not_an_answer))
;;

(* Higher-level function to get TXT records as strings *)
let get_txt_records ~sw ~net ~dst ~clock domain_name =
  match query_txt ~sw ~net ~dst ~clock domain_name with
  | Ok (ttl, records) ->
    Logs.info (fun m ->
      m "TXT records for %s (TTL=%ld): %d records" domain_name ttl (List.length records));
    Ok records
  | Error e ->
    Logs.warn (fun m -> m "Failed to query TXT for %s" domain_name);
    Error e
;;

(* Example: Get encryption key from DNS TXT record *)
let get_key ~sw ~net ~dst ~clock =
  match get_txt_records ~sw ~net ~dst ~clock "key.vpn.local" with
  | Ok (key :: _) -> Some key
  | Ok [] -> None
  | Error _ -> None
;;

(* TODO: setup search in resolv.conf *)
