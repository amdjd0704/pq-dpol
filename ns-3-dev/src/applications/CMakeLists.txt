find_external_library(

    DEPENDENCY_NAME oqs

    HEADER_NAMES oqs.h

    LIBRARY_NAMES oqs


  )


link_libraries(${oqs_LIBRARIES})


set(include_dir "~/dpol/ns-3-dev/src/applications/ivrf/")

include_directories(${include_dir})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

build_lib(
  LIBNAME applications
  SOURCE_FILES
    helper/bulk-send-helper.cc
    helper/on-off-helper.cc
    helper/packet-sink-helper.cc
    helper/three-gpp-http-helper.cc
    helper/udp-client-server-helper.cc
    helper/udp-echo-helper.cc
    model/application-packet-probe.cc
    model/bulk-send-application.cc
    model/onoff-application.cc
    model/packet-loss-counter.cc
    model/packet-sink.cc
    model/seq-ts-echo-header.cc
    model/seq-ts-header.cc
    model/seq-ts-size-header.cc
    model/three-gpp-http-client.cc
    model/three-gpp-http-header.cc
    model/three-gpp-http-server.cc
    model/three-gpp-http-variables.cc
    model/udp-client.cc
    model/udp-echo-client.cc
    model/udp-echo-server.cc
    model/udp-server.cc
    model/udp-trace-client.cc
    helper/network-helper.cc
    model/dpol-node.cc
    model/block.cc
    model/SHA.cc
    #model/raft-node.cc
    #model/pbft-node.cc
    #model/paxos-node.cc
    ivrf/ivrf.cc
    ivrf/drbg_rng.cc
    

    
  HEADER_FILES
    helper/bulk-send-helper.h
    helper/on-off-helper.h
    helper/packet-sink-helper.h
    helper/three-gpp-http-helper.h
    helper/udp-client-server-helper.h
    helper/udp-echo-helper.h
    model/application-packet-probe.h
    model/bulk-send-application.h
    model/onoff-application.h
    model/packet-loss-counter.h
    model/packet-sink.h
    model/seq-ts-echo-header.h
    model/seq-ts-header.h
    model/seq-ts-size-header.h
    model/three-gpp-http-client.h
    model/three-gpp-http-header.h
    model/three-gpp-http-server.h
    model/three-gpp-http-variables.h
    model/udp-client.h
    model/udp-echo-client.h
    model/udp-echo-server.h
    model/udp-server.h
    model/udp-trace-client.h
    helper/network-helper.h
    model/dpol-node.h
    model/block.h
    model/SHA.h
    #model/raft-node.h
    #model/pbft-node.h
    #model/paxos-node.h
    ivrf/ivrf.h
    ivrf/drbg_rng.h

    
  LIBRARIES_TO_LINK ${libinternet} 
                    ${libstats}
  TEST_SOURCES
    test/three-gpp-http-client-server-test.cc
    test/bulk-send-application-test-suite.cc
    test/udp-client-server-test.cc
)

