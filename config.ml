(* mirage >= 4.9.0 & < 4.12.0 *)

open Mirage

(* xenstore id 51712 is the root volume *)
let block = block_of_xenstore_id "51712"
let disk = tar_kv_ro block

let main =
  main
    ~packages:
      [
        package "vchan" ~min:"4.0.2";
        package "cstruct";
        package "tcpip" ~min:"3.7.0";
        package ~sublibs:[ "mirage" ] "arp" ~min:"4.1.0";
        package "ethernet" ~min:"3.0.0";
        package "shared-memory-ring" ~min:"3.0.0";
        package "mirage-net-xen" ~min:"2.1.8";
        package "ipaddr" ~min:"5.2.0";
        package "mirage-qubes" ~min:"2.0.1";
        package "mirage-nat" ~min:"3.0.1";
        package "mirage-logs";
        package "mirage-xen" ~min:"9.0.1";
        package "dns";
        package "dns-server";
      ]
    "Unikernel.Main" (kv_ro @-> job)

let () = register "qubes-dnshole" [ main $ disk ]
