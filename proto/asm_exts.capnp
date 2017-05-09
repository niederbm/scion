@0xe6c88f91b6a1209e;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct RoutingPolicyExt{
    set @0 :Bool;   # Is the extension present? Every extension must include this field.
    polType @1 :UInt8;  # The policy type
    ifID @2 :UInt64;
    isdases @3 :List(UInt32);
}

struct ISDAnnouncementExt{
    set @0 :Bool;   # TODO(Sezer): Implement announcement extension
    hashAlg @1 :UInt8; # Algorithm used for hashing
    hashValue @2 :Data;
    trc @3 :Data; # The newcomer TRC
    currentlyRejected @4 :Bool; # Stores wehter or not the currently handling BS rejected this announcement
}

struct AnnouncementRejectedExt{
    set @0 :Bool;
    indices @1 :List(UInt32);
}
