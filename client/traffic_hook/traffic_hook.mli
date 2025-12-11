(** Traffic Hook - Monitor egress packets to specific IP addresses using eBPF *)

(** Callback invoked when a packet to a target IP is detected *)
type callback = dst_ip:Ipaddr.t -> timestamp:int64 -> unit

(** [start ~interface ~target_subnets ?debounce_ms ~stop callback] monitors egress 
    packets on [interface] destined for any IP in the CIDR ranges [target_subnets].
    Blocks until [!stop] becomes true, invoking [callback] for each matching packet.
    
    @param interface Network interface name (e.g., "wg0", "eth0")
    @param target_subnets List of target subnets in CIDR notation
    @param debounce_ms Optional debounce interval in milliseconds (per destination IP)
    @param stop Reference that when set to [true] stops the monitor
    @param callback Function called when matching packet detected
    @raise Failure if interface not found, BPF load fails, or attach fails *)
val start
  :  interface:string
  -> target_subnets:Ipaddr.Prefix.t list
  -> ?debounce_ms:int
  -> stop:bool ref
  -> callback
  -> unit

(** [start_eio ~clock ~sw ~interface ~target_subnets ?debounce_ms callback] monitors egress 
    packets using Eio. Runs until the switch [sw] is cancelled or turned off.
    
    This integrates with Eio's structured concurrency - the hook is automatically
    cleaned up when the switch ends.
    
    @param clock Eio clock for polling intervals
    @param sw Eio switch that controls the lifetime of the hook
    @param interface Network interface name (e.g., "wg0", "eth0")
    @param target_subnets List of target subnets in CIDR notation
    @param debounce_ms Optional debounce interval in milliseconds (per destination IP)
    @param callback Function called when matching packet detected
    @raise Failure if interface not found, BPF load fails, or attach fails *)
val start_eio
  :  sw:Eio.Switch.t
  -> interface:string
  -> target_subnets:Ipaddr.Prefix.t list
  -> ?debounce_ms:int
  -> callback
  -> unit
