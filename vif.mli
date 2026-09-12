module Netif : module type of Netif.Make (Xenstore.Make (Xen_os.Xs))
module Eth : module type of Ethernet.Make (Netif)
module Client_arp : Arp.S
module Client_ip : module type of Static_ipv4.Make (Eth) (Client_arp)

type t = {
  ipaddr : Ipaddr.V4.t * Ipaddr.V4.t;
  mac : Macaddr.t * Macaddr.t;
  ethernet : Eth.t;
  arp : Client_arp.t;
  ip : Client_ip.t;
  domid : int;
  backend : Netif.t;
}

val make :
  Netif.t -> Dao.Client_vif.t -> gateway:Ipaddr.V4.t -> Ipaddr.V4.t -> t Lwt.t

val pp : t Fmt.t
