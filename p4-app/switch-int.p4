#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"

#include "includes/standard_h.p4" // Eth, IP, TCP/UDP
#include "includes/int_report_h.p4"
#include "includes/int_tcp_udp_h.p4"
#include "includes/headers.p4"

#include "includes/port_counters.p4"
#include "includes/controller_io.p4"

#include "includes/parsers.p4"

#include "includes/checksum.p4"
#include "includes/int.p4"
#include "includes/table0.p4"




control IngressImpl(inout headers_t hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    // from "includes/port_counters.p4"
    Port_counters_ingress() port_counters_ingress;
    // from "includes/controller_io.p4"
    Packetio_ingress() packetio_ingress;
    // from "includes/table0.p4"
    Table0_control() table0_control;
    // from "includes/int.p4"
    Int_ingress() int_ingress;


    apply{
        // We are using this control block to increment counters I believe
        //I believe I do not use for anything but the ONF version included it
        port_counters_ingress.apply(hdr, standard_metadata);
        // We are using this control block to check the traffic coming from the
        // controller. If packet_out, the send and exit. Else, enable packet_in header
        packetio_ingress.apply(hdr, standard_metadata);
        // We use this table to set the egress port, then use it to
        // set egress_spec. Very similar to a typical fwd table
        table0_control.apply(hdr, meta, standard_metadata);
        // We use this to indicate the processing stage at current switch
        // (using local metadata) to be first hop (important for source INT
        // header setting), or last hop
        int_ingress.apply(hdr, meta, standard_metadata);


        // Because we already decided where to send the packet, we can also know
        // if the switch is last hop. We only clone the INT packets
        if(hdr.int_shim.isValid() &&
            hdr.int_meta.isValid() && meta.int_metadata.last_hop == 1) {
            clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
            // Consider that cloned packets have a predefined output port that
            // you insert with a command (mirroring_add)
        }

    }
}

control EgressImpl(inout headers_t hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata)
{
    Port_counters_egress() port_counters_egress;
    Int_egress() int_egress;
    Packetio_egress() packetio_egress;

    apply{
        int_egress.apply(hdr, meta, standard_metadata);
        port_counters_egress.apply(hdr, standard_metadata);
        packetio_egress.apply(hdr, standard_metadata);

    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
