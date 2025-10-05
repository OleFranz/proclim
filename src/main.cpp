#include <thread>

#include "listener.h"
#include "throttle.h"


int main() {
    std::thread flow_thread(flow_layer_listener);
    std::thread network_thread(network_layer_listener);
    std::thread queue_thread(packet_queue_processor);

    flow_thread.join();
    network_thread.join();
    queue_thread.join();

    return 0;
}