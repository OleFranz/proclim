#include <thread>

#include "listener.h"


int main() {
    std::thread flow_thread(flow_layer_listener);
    std::thread network_thread(network_layer_listener);

    flow_thread.join();
    network_thread.join();
    return 0;
}