open Lwt
open Qubes
open Cmdliner

let ( let* ) = Lwt.bind
let ( % ) f g = fun x -> f (g x)

module UplinkEth = Ethernet.Make (Netif)
module Arp = Arp.Make (UplinkEth)

let src = Logs.Src.create "unikernel" ~doc:"Main unikernel code"

module Log = (val Logs.src_log src : Logs.LOG)

let blocklist_name =
  let doc =
    Arg.info
      ~doc:"Name in the tarball to fetch the blocked list of domains from"
      [ "blocklist-name" ]
  in
  Mirage_runtime.register_arg Arg.(value & opt string "tracking.txt" doc)

module Main (KV : Mirage_kv.RO) = struct
  type uplink = {
    mutable fragments : Fragments.Cache.t;
    net : Netif.t;
    eth : UplinkEth.t;
    arp : Arp.t;
    ip : Ipaddr.V4.t;
  }

  type t = {
    table : Mirage_nat_lru.t;
    uplink : uplink;
        (* dns0 and dns1 from qubesDB, and the resolver address from command line *)
    dns : Ipaddr.V4.t * Ipaddr.V4.t;
    clients : Clients.t;
  }

  let or_raise msg pp = function
    | Ok x -> x
    | Error e -> failwith (Fmt.str "%s: %a" msg pp e)

  (* Blocklist stuff *)
  let is_ip_address str =
    try
      ignore (Ipaddr.V4.of_string_exn str);
      true
    with Ipaddr.Parse_error (_, _) -> false

  (* a simple parser of files in the common blocking list format:
       # comment
       0.0.0.0 evil-domain.com *)
  let parse_domain_file str =
    let lines = String.split_on_char '\n' str in
    let lines =
      List.filter
        (fun l -> l <> "" && not (String.starts_with ~prefix:"#" l))
        lines
    in
    List.filter_map
      (fun l ->
        match String.split_on_char ' ' l with
        | [ ip; dom_name ] ->
            if is_ip_address dom_name then (
              Logs.warn (fun m -> m "ip address in hostname position: \"%s\"" l);
              None)
            else if String.equal "0.0.0.0" ip then Some dom_name
            else (
              Logs.warn (fun m -> m "non-0.0.0.0 ip in input file: %s" l);
              Some dom_name)
        | _ ->
            Logs.warn (fun m -> m "unexpected input line format: \"%s\"" l);
            None)
      lines

  (* declare these pairs up front, so that they'll only be allocated once *)
  let ipv6_pair = (3600l, Ipaddr.V6.(Set.singleton localhost))
  let ipv4_pair = (3600l, Ipaddr.V4.(Set.singleton localhost))
  let soa = Dns.Soa.create (Domain_name.of_string_exn "localhost")

  let add_dns_entries str t =
    Logs.debug (fun m -> m "adding domain: \"%s\"" str);
    match Domain_name.of_string str with
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "Invalid domain name: %s" msg);
        t
    | Ok name ->
        let t = Dns_trie.insert name Dns.Rr_map.Aaaa ipv6_pair t in
        let t = Dns_trie.insert name Dns.Rr_map.A ipv4_pair t in
        let t = Dns_trie.insert name Dns.Rr_map.Soa soa t in
        t

  (* Helpers *)
  let compare a b = Ipaddr.V4.compare a b = 0

  let command_handler ~user:_ cmd _flow =
    match cmd with
    | "QUBESRPC qubes.WaitForSession none" -> return 0 (* Always ready! *)
    | cmd ->
        Log.warn (fun f -> f "Unknown command %S" cmd);
        return 1

  (* Write a Nat_packet to the uplink interface *)
  let to_upstream t packet =
    Lwt.catch
      (fun () ->
        let uplink = t.uplink.eth in
        let fragments = ref [] in
        ( UplinkEth.write uplink (UplinkEth.mac uplink) `IPv4 (fun b ->
              match Nat_packet.into_cstruct packet b with
              | Error e ->
                  Log.warn (fun f ->
                      f "Failed to write packet: %a" Nat_packet.pp_error e);
                  0
              | Ok (n, frags) ->
                  fragments := frags;
                  n)
        >|= function
          | Ok () -> ()
          | Error _e -> Log.err (fun f -> f "error trying to send to upstream")
        )
        >>= fun () ->
        Lwt_list.iter_s
          (fun f ->
            let size = Cstruct.length f in
            UplinkEth.write uplink (UplinkEth.mac uplink) `IPv4 (fun b ->
                Cstruct.blit f 0 b 0 size;
                size)
            >|= function
            | Ok () -> ()
            | Error _e ->
                Log.err (fun f -> f "error trying to send to upstream"))
          !fragments)
      (fun ex ->
        Log.err (fun f ->
            f "uncaught exception trying to send to uplink: %s"
              (Printexc.to_string ex));
        Lwt.return_unit)

  (* Write a Nat_packet to the vif interface *)
  let to_client vif packet =
    Lwt.catch
      (fun () ->
        let fragments = ref [] in
        ( Vif.Client_ethernet.write vif.Vif.ethernet (snd vif.mac) `IPv4
            (fun b ->
              match Nat_packet.into_cstruct packet b with
              | Error e ->
                  Log.warn (fun f ->
                      f "Failed to write packet: %a" Nat_packet.pp_error e);
                  0
              | Ok (n, frags) ->
                  fragments := frags;
                  n)
        >|= function
          | Ok () -> ()
          | Error _e -> Log.err (fun f -> f "error trying to send to client") )
        >>= fun () ->
        Lwt_list.iter_s
          (fun f ->
            let size = Cstruct.length f in
            Vif.Client_ethernet.write vif.Vif.ethernet (snd vif.mac) `IPv4
              (fun b ->
                Cstruct.blit f 0 b 0 size;
                size)
            >|= function
            | Ok () -> ()
            | Error _e -> Log.err (fun f -> f "error trying to send to client"))
          !fragments)
      (fun ex ->
        (* Usually Netback_shutdown, because the client disconnected *)
        Log.err (fun f ->
            f "uncaught exception trying to send to client: %s"
              (Printexc.to_string ex));
        Lwt.return_unit)

  (* Translate the packet according to the NAT table *)
  let translate t packet =
    match Mirage_nat_lru.translate t.table packet with
    | Ok packet -> Some packet
    | Error `Untranslated ->
        Log.debug (fun f -> f "Failed to NAT %a" Nat_packet.pp packet);
        None
    | Error `TTL_exceeded ->
        (* TODO(dinosaure): should report ICMP error message to src. *)
        Logs.warn (fun m -> m "TTL exceeded");
        None

  (* Add the packet to the NAT table, and forward uplink it afterward *)
  let nat_and_forward t packet =
    match
      Mirage_nat_lru.add t.table packet t.uplink.ip
        (fun () -> Some (Randomconv.int16 Mirage_crypto_rng.generate))
        `NAT
    with
    | Error err ->
        Logs.warn (fun m ->
            m "Failed to add a NAT rule: %a" Mirage_nat.pp_error err);
        Lwt.return_unit
    | Ok () -> (
        (* In all other cases, forward to uplink *)
        match translate t packet with
        | Some packet -> to_upstream t packet
        | None -> Lwt.return_unit)

  (* clients packets to upstream *)
  let handle_private t primary_t vif packet =
    let _ = Qubes.Misc.check_memory ~fraction:20 () in
    (* TODO: do something when Memory_critical is returned *)
    match Mirage_nat_lru.translate t.table packet with
    | Ok packet -> to_upstream t packet
    | Error `TTL_exceeded ->
        Logs.warn (fun m -> m "TTL exceeded");
        Lwt.return_unit
    | Error `Untranslated ->
        (* A new flow packet *)
        let (`IPv4 (hdr, payload)) = packet in
        let dns0, dns1 = t.dns in
        (* Let's check if we have a DNS packet, otherwise forward it upstream *)
        if compare dns0 hdr.Ipv4_packet.dst || compare dns1 hdr.Ipv4_packet.dst
        then
          match
            match payload with
            | `TCP (tcp, payload) ->
                let tcp_hdr =
                  {
                    tcp with
                    src_port = tcp.Tcp.Tcp_packet.dst_port;
                    dst_port = tcp.Tcp.Tcp_packet.src_port;
                  }
                in
                Some (`TCP tcp_hdr, payload)
            | `UDP (udp, payload) ->
                let udp_hdr : Udp_packet.t =
                  {
                    src_port = udp.Udp_packet.dst_port;
                    dst_port = udp.Udp_packet.src_port;
                  }
                in
                Some (`UDP udp_hdr, payload)
            | `ICMP _ -> None
          with
          | None ->
              (* ICMP for Qubes DNS addresses: forward uplink otherwise many fail to NAT logs will appears :) *)
              nat_and_forward t packet
          | Some (l4_hdr, payload) -> (
              match Dns.Packet.decode (Cstruct.to_string payload) with
              | Error _ ->
                  (* Unable to decode the packet: drop *)
                  Lwt.return_unit
              | Ok dns_packet -> (
                  match
                    (dns_packet.Dns.Packet.data, dns_packet.Dns.Packet.question)
                  with
                  | `Query, (name, `Any) | `Query, (name, `K _) -> (
                      match
                        Dns_trie.entries name
                          (Dns_server.Primary.data primary_t)
                      with
                      | Error _ ->
                          (* The domain is not found in the blocking list, forward upstream for resolution *)
                          nat_and_forward t packet
                      | Ok (_soa, _map) ->
                          (* construct a Nat_packet for that client with a DNS answer saying that the name is associated with localhost *)
                          let ip_hdr : Ipv4_packet.t =
                            {
                              hdr with
                              src = hdr.Ipv4_packet.dst;
                              dst = hdr.Ipv4_packet.src;
                            }
                          in
                          (* TODO: create the correct Cstruct *)
                          let reply = Cstruct.empty in
                          let ip_payload =
                            match l4_hdr with
                            | `TCP tcp -> `TCP (tcp, reply)
                            | `UDP udp -> `UDP (udp, reply)
                            | _ -> assert false (* ICMP should not be here *)
                          in
                          let nat_packet : Nat_packet.t =
                            `IPv4 (ip_hdr, ip_payload)
                          in
                          to_client vif nat_packet)
                  | _ ->
                      (* Every other DNS packets from client: drop? *)
                      Lwt.return_unit))
        else nat_and_forward t packet

  (* uplink packets uplink to the destination client *)
  let handle_uplink t packet =
    let _ = Qubes.Misc.check_memory ~fraction:20 () in
    match translate t packet with
    | Some frame -> (
        let (`IPv4 (hdr, _payload)) = frame in
        let dest = hdr.Ipv4_packet.dst in
        match Clients.lookup t.clients dest with
        | Some vif ->
            Logs.debug (fun m -> m "Sending a packet to %a" Ipaddr.V4.pp dest);
            to_client vif frame
        | None ->
            Logs.warn (fun m ->
                m "%a does not exist as a client" Ipaddr.V4.pp dest);
            Lwt.return_unit)
    | None ->
        Logs.debug (fun m -> m "Not translated");
        Lwt.return_unit

  (* wait for uplink packets and put them into [t.oc] *)
  let uplink_loop t =
    Netif.listen t.uplink.net ~header_size:Ethernet.Packet.sizeof_ethernet
      (fun frame ->
        let now = Mirage_mtime.elapsed_ns () in
        (* Handle one Ethernet frame from NetVM *)
        UplinkEth.input t.uplink.eth ~arpv4:(Arp.input t.uplink.arp)
          ~ipv4:(fun ip ->
            let fragments, r =
              Nat_packet.of_ipv4_packet t.uplink.fragments ~now ip
            in
            t.uplink.fragments <- fragments;
            match r with
            | Error e ->
                Log.warn (fun f ->
                    f "Ignored unknown IPv4 message from uplink: %a"
                      Nat_packet.pp_error e);
                Lwt.return_unit
            | Ok None -> Lwt.return_unit
            | Ok (Some packet) -> handle_uplink t packet)
          ~ipv6:(fun _ip -> Lwt.return_unit)
          frame)
    >|= or_raise "Uplink listen loop" Netif.pp_error

  (* Create a vif dedicated for a new client *)
  let add_vif t primary_t ~finalisers
      ({ Dao.Client_vif.domid; device_id } as client_vif) ipaddr () =
    let open Lwt.Infix in
    let* backend = Vif.Netbackend.make ~domid ~device_id in
    let gateway = Clients.default_gateway t.clients in
    let* vif = Vif.make backend client_vif ~gateway ipaddr in
    let* () = Clients.add_client t.clients vif in
    Finaliser.add
      ~finaliser:(fun () -> Clients.rem_client t.clients vif)
      finalisers;
    let fragment_cache = ref (Fragments.Cache.empty (256 * 1024)) in

    let listener =
      let fn () =
        let arpv4 = Vif.Client_arp.input vif.Vif.arp in
        let ipv4 vif packet =
          let cache', r =
            Nat_packet.of_ipv4_packet !fragment_cache
              ~now:(Mirage_mtime.elapsed_ns ())
              packet
          in
          fragment_cache := cache';
          match r with
          | Error e ->
              Log.warn (fun f ->
                  f "Ignored unknown IPv4 message: %a" Nat_packet.pp_error e);
              Lwt.return_unit
          | Ok None -> Lwt.return_unit
          | Ok (Some packet) -> handle_private t primary_t vif packet
        in
        let header_size = Ethernet.Packet.sizeof_ethernet
        and input frame =
          match Ethernet.Packet.of_cstruct frame with
          | Error err ->
              Log.warn (fun f -> f "Invalid Ethernet frame: %s" err);
              Lwt.return_unit
          | Ok (eth, payload) -> (
              match eth.Ethernet.Packet.ethertype with
              | `ARP -> arpv4 payload
              | `IPv4 -> ipv4 vif payload
              | `IPv6 -> Lwt.return_unit)
        in
        Logs.debug (fun m -> m "%a starts to listen packets" Vif.pp vif);
        Vif.Netbackend.listen backend ~header_size input >>= function
        | Error err ->
            Logs.err (fun m ->
                m "Private interface %a stopped: %a" Vif.Netbackend.pp_error err
                  Vif.pp vif);
            Lwt.return_unit
        | Ok () ->
            Logs.debug (fun m ->
                m "Private interface %a terminated normally" Vif.pp vif);
            Lwt.return_unit
      in
      Lwt.catch fn @@ function
      | Lwt.Canceled -> Lwt.return_unit
      | exn -> Lwt.fail exn
    in
    Finaliser.add ~finaliser:(fun () -> Lwt.cancel listener) finalisers;
    Lwt.async (fun () -> listener);
    Lwt.return finalisers

  (* Handles the connexion with a new client *)
  let add_client t primary_t client_vif ipaddr =
    let finalisers = Finaliser.create () in
    Lwt.catch (add_vif t primary_t ~finalisers client_vif ipaddr) @@ function
    | exn ->
        Logs.warn (fun f ->
            f "Error with client %a: %s" Dao.Client_vif.pp client_vif
              (Printexc.to_string exn));
        Lwt.return finalisers

  (* Waits for new clients *)
  let wait_clients t primary_t =
    let clients : Finaliser.t Dao.Vif_map.t ref = ref Dao.Vif_map.empty in
    Dao.watch_clients @@ fun m ->
    Logs.debug (fun m -> m "The network topology was updated");
    let clean_up_clients client_vif finalisers =
      if not (Dao.Vif_map.mem client_vif m) then (
        clients := Dao.Vif_map.remove client_vif !clients;
        Logs.info (fun f -> f "client %a has gone" Dao.Client_vif.pp client_vif);
        Finaliser.finalise finalisers)
    in
    let rec add_new_clients seq =
      match Seq.uncons seq with
      | Some ((client_vif, ipaddr), seq)
        when not (Dao.Vif_map.mem client_vif !clients) ->
          let* finalisers = add_client t primary_t client_vif ipaddr in
          Logs.debug (fun f ->
              f "client %a arrived" Dao.Client_vif.pp client_vif);
          clients := Dao.Vif_map.add client_vif finalisers !clients;
          add_new_clients seq
      | Some (_, seq) -> add_new_clients seq
      | None -> Lwt.return_unit
    in
    Logs.debug (fun m -> m "Clean-up clients");
    Dao.Vif_map.iter clean_up_clients !clients;
    let open Lwt.Infix in
    Logs.debug (fun m -> m "Add new clients");
    add_new_clients (Dao.Vif_map.to_seq m) >|= fun () ->
    Logs.debug (fun m -> m "The unikernel is in-sync with the network topology")

  (* Main unikernel entry point (called from auto-generated main.ml). *)
  let start disk =
    let open Lwt.Syntax in
    let start_time = Mirage_mtime.elapsed_ns () in
    (* Start qrexec agent and QubesDB agent in parallel *)
    let* qrexec = RExec.connect ~domid:0 () in
    let agent_listener = RExec.listen qrexec command_handler in

    let* qubesDB = DB.connect ~domid:0 () in

    let startup_time =
      let ( - ) = Int64.sub in
      let time_in_ns = Mirage_mtime.elapsed_ns () - start_time in
      Int64.to_float time_in_ns /. 1e9
    in
    Log.info (fun f ->
        f "QubesDB and qrexec agents connected in %.3f s" startup_time);

    (* Set up networking *)
    let nat =
      Mirage_nat_lru.empty ~tcp_size:1024 ~udp_size:1024 ~icmp_size:20
    in

    let blocklist_name = blocklist_name () in
    Log.info (fun m -> m "parsing %s" blocklist_name);
    let* content = KV.get disk (Mirage_kv.Key.v blocklist_name) in
    let domains =
      match content with
      | Error _ ->
          Logs.err (fun m ->
              m
                "Expected blocklist file '%s' is absent in the root volume.\n\
                 Try to run in dom0:\n\
                \  qvm-volume import mirage-vpn:root blocklist.tar\n\
                 with the tarball containing the blocklist file."
                blocklist_name);
          Fmt.failwith "No Blocklist found"
      | Ok list -> parse_domain_file list
    in
    let trie = List.fold_right add_dns_entries domains Dns_trie.empty in
    let primary_t =
      Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate trie
    in
    Logs.debug (fun m -> m "Blocklist file loaded");

    Netif.connect "0" >>= fun net ->
    UplinkEth.connect net >>= fun eth ->
    Arp.connect eth >>= fun arp ->
    let* cfg = Dao.read_network_config qubesDB in
    let clients = Clients.create cfg in

    (* Report memory usage to XenStore *)
    let fragments_cache = Fragments.Cache.empty (256 * 1024) in
    let t =
      {
        table = nat;
        uplink = { fragments = fragments_cache; net; eth; arp; ip = cfg.Dao.ip };
        dns = (fst cfg.Dao.dns, snd cfg.Dao.dns);
        clients;
      }
    in

    (* Run until something fails or we get a shutdown request. *)
    let* () =
      Lwt.pick
        [
          agent_listener;
          Qubes.Misc.shutdown;
          uplink_loop t;
          wait_clients t primary_t;
        ]
    in

    (* Give the console daemon time to show any final log messages. *)
    Mirage_sleep.ns (1.0 *. 1e9 |> Int64.of_float)
end
