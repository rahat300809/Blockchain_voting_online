#define main original_main
#include "core.cpp"
#undef main

int main() {
    Blockchain bc;
    bc.load_blockchain();

    polling_agent_panel(bc);
}